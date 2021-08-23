import * as pulumi from '@pulumi/pulumi';
import * as aws from '@pulumi/aws';
import * as random from '@pulumi/random';
import { ResourceError } from '@pulumi/pulumi';
import {
    FargateServiceArgs,
    FargateServiceDefaults,
    FargateServiceArgsWithDefaults,
    SecretFromInput,
    FargateContainerDefinition,
} from './types';
import { validCpuMemoryCombinations } from './constants';

export default class FargateService extends pulumi.ComponentResource {
    readonly executionRole: aws.iam.Role;

    readonly service: aws.ecs.Service;

    readonly taskDefinition: aws.ecs.TaskDefinition;

    readonly taskRole: aws.iam.Role;

    constructor(name: string, args: FargateServiceArgs, opts?: pulumi.ComponentResourceOptions) {
        super('FargateService', name, args, opts);

        const {
            albConfig,
            autoScalingConfig,
            clusterName,
            containers,
            cpu,
            memory,
            desiredCount,
            minimumHealthyPercent,
            namespace,
            subnetIds,
            taskPolicy,
            vpcId,
            securityGroupIds,
        } = this.validateArgs(args, {
            cpu: 256,
            memory: 512,
            desiredCount: 1,
            minimumHealthyPercent: 100,
            namespace: `${name}-${pulumi.getStack()}`,
        });

        const region = aws.config.requireRegion();
        const { accountId } = pulumi.output(aws.getCallerIdentity());

        // A role that AWS assumes in order to *launch* the task (not the role that the task itself assumes)
        const executionRole = new aws.iam.Role(
            `${namespace}-execution-role`,
            {
                description: `Allows the AWS ECS service to create and manage the ${namespace} service`,
                assumeRolePolicy: {
                    Version: '2012-10-17',
                    Statement: [
                        {
                            Effect: 'Allow',
                            Principal: { Service: 'ecs-tasks.amazonaws.com' },
                            Action: 'sts:AssumeRole',
                        },
                    ],
                },
            },
            { parent: this },
        );

        // AWS-managed policy giving the above role some basic permissions it needs
        const executionPolicyBasic = new aws.iam.RolePolicyAttachment(
            'basic-ecs-policy',
            {
                policyArn: 'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy',
                role: executionRole,
            },
            { parent: executionRole },
        );

        const logGroupArns = containers.reduce((arns, { logGroupName }) => {
            if (logGroupName) {
                arns.push(pulumi.interpolate`arn:aws:logs:${region}:${accountId}:log-group:/${logGroupName}:*`);
            }
            return arns;
        }, [] as pulumi.Input<string>[]);

        if (logGroupArns.length > 0) {
            // Policy allowing ECS to write to the all relevant log groups
            const executionPolicyLogs = new aws.iam.RolePolicy(
                'logs-policy',
                {
                    role: executionRole,
                    policy: {
                        Version: '2012-10-17',
                        Statement: [
                            {
                                Effect: 'Allow',
                                Action: ['logs:CreateLogStream', 'logs:PutLogEvents'],
                                Resource: logGroupArns,
                            },
                        ],
                    },
                },
                { parent: executionRole },
            );
        }

        // Build an array of Policy Statements allowing access to any secrets
        const secretStatements: aws.iam.PolicyStatement[] = [];

        const allSecrets = containers.reduce(
            (secrets, container) => (container.secrets ? [...secrets, ...container.secrets] : secrets),
            [] as SecretFromInput[],
        );

        // If secrets have been supplied, create policies allowing access to them
        if (allSecrets.length > 0) {
            const smSecrets = allSecrets.filter((s) => s.source === 'secrets-manager').map((s) => s.valueFromArn);
            const psSecrets = allSecrets.filter((s) => s.source === 'parameter-store').map((s) => s.valueFromArn);

            if (smSecrets.length > 0) {
                const uniqueArns = pulumi.all(smSecrets).apply((arns) => [...new Set(arns)]);

                secretStatements.push({
                    Sid: 'AllowSecretsManagerSecrets',
                    Effect: 'Allow',
                    Action: 'secretsmanager:GetSecretValue',
                    Resource: uniqueArns,
                });
            }

            if (psSecrets.length > 0) {
                const uniqueArns = pulumi.all(psSecrets).apply((arns) => [...new Set(arns)]);

                secretStatements.push({
                    Sid: 'AllowSsmParameters',
                    Effect: 'Allow',
                    Action: 'ssm:GetParameter*',
                    Resource: uniqueArns,
                });
            }
        }

        // We'll also need a policy allowing access to any supplied repository credentials
        const repositoryCredentialArns = containers
            .map((container) => container.repositoryCredentialsArn)
            // Remove any undefined values so TypeScript knows
            .filter((arn): arn is pulumi.Input<string> => !!arn);

        if (repositoryCredentialArns.length > 0) {
            secretStatements.push({
                Sid: 'AllowRepositoryCredentials',
                Effect: 'Allow',
                Action: 'secretsmanager:GetSecretValue',
                Resource: repositoryCredentialArns,
            });
        }

        if (secretStatements.length > 0) {
            const secretsPolicy = new aws.iam.RolePolicy(
                'container-secrets-policy',
                {
                    role: executionRole,
                    name: 'secrets-policy',
                    policy: {
                        Version: '2012-10-17',
                        Statement: secretStatements,
                    },
                },
                { parent: executionRole },
            );
        }

        // The role the actual task itself will assume
        const taskRole = new aws.iam.Role(
            `${namespace}-task-role`,
            {
                assumeRolePolicy: {
                    Version: '2012-10-17',
                    Statement: [
                        {
                            Effect: 'Allow',
                            Principal: {
                                Service: 'ecs-tasks.amazonaws.com',
                            },
                            Action: 'sts:AssumeRole',
                        },
                    ],
                },
            },
            { parent: this },
        );

        if (taskPolicy) {
            const taskRolePolicy = new aws.iam.RolePolicy(
                `${namespace}-role-policy`,
                {
                    role: taskRole,
                    policy: taskPolicy,
                },
                { parent: taskRole },
            );
        }

        const randomId = new random.RandomId(
            'task-definition-family-id',
            {
                byteLength: 4,
            },
            { parent: this },
        );

        const taskDefinition = new aws.ecs.TaskDefinition(
            `${namespace}-task-definition`,
            {
                family: pulumi.interpolate`${namespace}-${randomId.hex}`,
                executionRoleArn: executionRole.arn,
                taskRoleArn: taskRole.arn,
                networkMode: 'awsvpc',
                requiresCompatibilities: ['FARGATE'],
                cpu: cpu.toString(),
                memory: memory.toString(),
                containerDefinitions: this.generateAwsContainerDefinitions(containers).apply((defs) =>
                    JSON.stringify(defs),
                ),
            },
            { parent: this },
        );

        const containerAlbConfigs: aws.types.input.ecs.ServiceLoadBalancer[] = [];
        const serviceOpts: pulumi.ResourceOptions = {};
        let targetGroupArnSuffix: pulumi.Output<string> | string = '';

        if (albConfig) {
            const { healthCheckConfig, listenerArn, ruleActions, rulePriority, portMapping, path } = albConfig;

            const targetGroup = new aws.lb.TargetGroup(
                `${namespace}-tg`,
                {
                    deregistrationDelay: 10,
                    vpcId,
                    targetType: 'ip',
                    port: portMapping.containerPort,
                    protocol: 'HTTP',
                    slowStart: 30,
                    healthCheck: healthCheckConfig,
                },
                { parent: this },
            );

            targetGroupArnSuffix = targetGroup.arnSuffix;

            const actions: aws.types.input.lb.ListenerRuleAction[] = [];

            if (ruleActions) ruleActions.forEach((action, index) => actions.push({ order: index + 1, ...action }));

            actions.push({
                order: ruleActions?.length ? ruleActions.length + 1 : 1,
                type: 'forward',
                targetGroupArn: targetGroup.arn,
            });

            const listenerRule = new aws.lb.ListenerRule(
                `${namespace}-listener-rule`,
                {
                    priority: rulePriority,
                    listenerArn,
                    conditions: [{ pathPattern: { values: [path ?? '/*'] } }],
                    actions,
                },
                { parent: this, deleteBeforeReplace: true },
            );

            containerAlbConfigs.push({ ...portMapping, targetGroupArn: targetGroup.arn });

            // The service needs to depend on the listener rule since AWS will not add a service to a target group until
            // the target group is associated with a listener which doesn't occur until the listener rule is created.
            // This lets Pulumi know of this implicit dependency so it won't try (and fail) to create the service
            serviceOpts.dependsOn = listenerRule;
        }

        const service = new aws.ecs.Service(
            `${namespace}-service`,
            {
                loadBalancers: containerAlbConfigs,
                cluster: clusterName,
                launchType: 'FARGATE',
                desiredCount,
                deploymentMinimumHealthyPercent: minimumHealthyPercent,
                taskDefinition: taskDefinition.arn,
                waitForSteadyState: true,
                networkConfiguration: {
                    securityGroups: securityGroupIds,
                    subnets: subnetIds,
                },
            },
            {
                parent: this,
                // If autoscaling is set up we need to ignore changes to desired count on update as it will likely have
                // changed due to autoscaling.
                ignoreChanges: autoScalingConfig ? ['desiredCount'] : [],
                ...serviceOpts,
            },
        );

        if (autoScalingConfig) {
            const { minTasks, maxTasks, scaleInCooldown, scaleOutCooldown, scalableMetric, threshold } =
                autoScalingConfig;

            const autoScalingTarget = new aws.appautoscaling.Target(
                `${namespace}-auto-scaling-target`,
                {
                    minCapacity: minTasks,
                    maxCapacity: maxTasks,
                    serviceNamespace: 'ecs',
                    resourceId: pulumi.interpolate`service/${clusterName}/${service.name}`,
                    scalableDimension: 'ecs:service:DesiredCount',
                },
                {
                    parent: this,
                },
            );

            let resourceLabel: pulumi.Input<string> | undefined;

            // If we're using ALBRequestCountPerTarget as the scalable metric, we need to figure out the 'ResourceLabel'
            // that the auto-scaling policy needs. It needs to be the concatentation of the ALB ARN Suffix and the
            // target group suffix.
            // https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PredefinedMetricSpecification.html
            if (scalableMetric === 'ALBRequestCountPerTarget') {
                // This should never happen since we check for it in validateArgs
                if (albConfig === undefined)
                    throw new ResourceError(
                        'You must supply ALB config if using ALBRequestCountPerTarget as the auto-scaling metric',
                        this,
                    );

                const albArnSuffix = pulumi
                    .output(albConfig.listenerArn)
                    .apply((arn) => this.getAlbArnSuffixFromListenerArn(arn));

                resourceLabel = pulumi.interpolate`${albArnSuffix}/${targetGroupArnSuffix}`;
            }

            const autoScalingPolicy = new aws.appautoscaling.Policy(
                `${namespace}-auto-scaling-policy`,
                {
                    policyType: 'TargetTrackingScaling',
                    resourceId: autoScalingTarget.id,
                    scalableDimension: 'ecs:service:DesiredCount',
                    serviceNamespace: 'ecs',
                    targetTrackingScalingPolicyConfiguration: {
                        predefinedMetricSpecification: {
                            resourceLabel,
                            predefinedMetricType: scalableMetric,
                        },
                        scaleInCooldown: scaleInCooldown ?? 60,
                        scaleOutCooldown: scaleOutCooldown ?? 60,
                        targetValue: threshold,
                    },
                },
                {
                    parent: this,
                },
            );
        }

        this.executionRole = executionRole;
        this.service = service;
        this.taskDefinition = taskDefinition;
        this.taskRole = taskRole;

        // https://www.pulumi.com/docs/intro/concepts/resources/#registering-component-outputs
        this.registerOutputs();
    }

    private generateAwsContainerDefinitions(input: FargateContainerDefinition[]) {
        return pulumi.output(input.map((def) => this.generateAwsContainerDefinition(def)));
    }

    /**
     * Converts the type FargateContainerDefinition (defined by this code) into a aws.ecs.ContainerDefinition
     */
    private generateAwsContainerDefinition(input: FargateContainerDefinition) {
        const { repositoryCredentialsArn, secrets: inputSecrets, logGroupName, environment } = input;

        const secretsResult = inputSecrets?.map(({ name, valueFromArn, key }) => ({
            name,
            valueFrom: key ? pulumi.interpolate`${valueFromArn}:${key}` : valueFromArn,
        }));

        const logConfigurationResult = logGroupName
            ? {
                  logDriver: 'awslogs',
                  options: {
                      'awslogs-region': aws.config.requireRegion().toString(),
                      'awslogs-group': input.logGroupName,
                      'awslogs-stream-prefix': input.name,
                  },
              }
            : undefined;

        const repositoryCredentials = repositoryCredentialsArn
            ? { credentialsParameter: repositoryCredentialsArn }
            : undefined;

        // Convert object into array of name/value pairs
        const environmentResult = environment
            ? Object.entries(environment).map(([name, value]) => ({
                  name,
                  value,
              }))
            : undefined;

        return pulumi
            .all([pulumi.output(input), secretsResult, logConfigurationResult])
            .apply(([args, secrets, logConfiguration]) => ({
                command: args.command,
                cpu: args.cpu,
                dependsOn: args.dependsOn,
                disableNetworking: args.disableNetworking,
                dnsSearchDomains: args.dnsSearchDomains,
                dnsServers: args.dnsServers,
                dockerLabels: args.dockerLabels,
                entryPoint: args.entryPoint,
                environment: environmentResult,
                essential: args.essential,
                extraHosts: args.extraHosts,
                firelensConfiguration: args.firelensConfiguration,
                healthCheck: args.healthCheck,
                image: args.image,
                interactive: args.interactive,
                linuxParameters: args.linuxParameters,
                logConfiguration,
                memory: args.memory,
                memoryReservation: args.memoryReservation,
                mountPoints: args.mountPoints,
                name: args.name,
                portMappings: args.portMappings,
                privileged: args.privileged,
                pseudoTerminal: args.pseudoTerminal,
                readonlyRootFilesystem: args.readonlyRootFilesystem,
                repositoryCredentials,
                resourceRequirements: args.resourceRequirements,
                secrets,
                startTimeout: args.startTimeout,
                stopTimeout: args.stopTimeout,
                systemControls: args.systemControls,
                ulimits: args.ulimits,
                user: args.user,
                volumesFrom: args.volumesFrom,
                workingDirectory: args.workingDirectory,
            }));
    }

    /**
     * Given a Listener ARN, return the ALB suffix portion. For example, given the following listener ARN:
     *
     * arn:aws:elasticloadbalancing:eu-west-1:012345678901:listener/app/name-of-alb/24cc901288efd990/eacc674b53cedc2d
     *
     * The output should be:
     *
     * app/name-of-alb/24cc901288efd990
     */
    private getAlbArnSuffixFromListenerArn(arn: string): string {
        const match =
            /^arn:aws:elasticloadbalancing:[^:]+:\d{12}:listener\/(?<albArnSuffix>app\/[^/]+\/[a-f0-9]+)\/[a-f0-9]+$/.exec(
                arn,
            );

        if (match === null || match.groups === undefined || !('albArnSuffix' in match.groups))
            throw new ResourceError(`Unable to find ALB ARN Suffix in ${arn}`, this);

        return match.groups.albArnSuffix;
    }

    private validateArgs(input: FargateServiceArgs, defaults: FargateServiceDefaults): FargateServiceArgsWithDefaults {
        const errors: string[] = [];
        const args = { ...defaults, ...input };

        // CPU and Memory validation
        if (!validCpuMemoryCombinations.includes(`${args.cpu}x${args.memory}`)) {
            errors.push(
                `CPU: ${args.cpu} and Memory: ${args.memory} is an unsupported combination, see https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html for valid combinations`,
            );
        }

        const sumOfCpuAllocation = args.containers.reduce((sum, c) => (c.cpu ? sum + c.cpu : sum), 0);

        if (sumOfCpuAllocation > args.cpu) {
            errors.push(
                `Sum of CPU allocation for all containers ${sumOfCpuAllocation} exceeds the CPU limit set for the task ${args.cpu}`,
            );
        }

        const sumOfMemoryAllocation = args.containers.reduce((sum, c) => (c.memory ? sum + c.memory : sum), 0);

        if (sumOfMemoryAllocation > args.memory) {
            errors.push(
                `Sum of memory allocation for all containers ${sumOfMemoryAllocation} exceeds the memory limit set for the task ${args.memory}`,
            );
        }

        // Namespace - must be <= 22 characters. Anything longer means the target group physical name will exceed the 32
        // character limit defined by AWS.
        // 22 + random-7-letter-suffix + '-tg' = 32
        if (args.namespace.length > 22) {
            errors.push(
                `Namespace cannot be longer than 22 characters. "${args.namespace}" is ${args.namespace.length} characters`,
            );
        }

        const priority = args.albConfig?.rulePriority;

        // Listener rule priority must be between 1 and 50,000
        if (priority && (priority < 1 || priority > 50_000)) {
            errors.push(`Listener rule priority must be between 1 and 50,000`);
        }

        // If scalableMetric is set to 'ALBRequestCountPerTarget' then load balancer configuration must also be supplied
        if (args.autoScalingConfig?.scalableMetric === 'ALBRequestCountPerTarget' && args.albConfig === undefined) {
            errors.push('You must supply ALB config if using ALBRequestCountPerTarget as the auto-scaling metric');
        }

        // Need to supply at least one security group id
        if (args.securityGroupIds.length < 1) {
            errors.push('You must supply at least one security group ID');
        }

        // Ensure all container definitions have a unique name
        const containerNames = args.containers.map((def) => def.name);
        const uniques = [...new Set(containerNames)];

        if (containerNames.length !== uniques.length) {
            errors.push(`All container names must be unique`);
        }

        // Courtesy check to ensure that the container mentioned in ALB config actually has some port mappings set up
        if (args.albConfig) {
            const { containerName, containerPort } = args.albConfig.portMapping;

            const matchingContainers = args.containers.filter((container) => container.name === containerName);

            if (matchingContainers.length < 1) {
                errors.push(
                    `You have configured the ALB to route traffic to port ${containerPort} on the ${containerName} container but that container has not been defined`,
                );
            } else {
                const container = matchingContainers[0];

                if (container.portMappings === undefined) {
                    errors.push(
                        `You have configured the ALB to route traffic to port ${containerPort} on the ${containerName} container, but the container definition does not have any port mappings. Add the portMappings property to the ${containerName} container definition`,
                    );
                } else {
                    const matchingPortMappings = container.portMappings.filter(
                        (mappings) => mappings.containerPort === containerPort,
                    );

                    if (matchingPortMappings.length !== 1) {
                        errors.push(
                            `You have configured the ALB to route traffic to port ${containerPort} on the ${containerName} container, but port ${containerPort} is not present in the container's portMappings property`,
                        );
                    }
                }
            }
        }

        if (errors.length > 0) {
            const errStr = errors.reduce((str, err) => `${str}\t- ${err}\n`, '');

            throw new pulumi.ResourceError(`Invalid FargateService args:\n${errStr}`, this);
        }

        return args;
    }
}
