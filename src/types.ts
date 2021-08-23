import * as pulumi from '@pulumi/pulumi';
import * as aws from '@pulumi/aws';

export interface SecretFromInput {
    /**
     * Name of the environment variable that will contain the secret value.
     *
     * Eg `MY_PASSWORD`
     */
    name: string;

    /**
     * Full ARN to a secrets manager or parameter store secret resource that contains your secret.
     */
    valueFromArn: pulumi.Input<string>;

    /**
     * The source of the secret, either `parameter-store` or `secrets-manager`.
     */
    source: 'parameter-store' | 'secrets-manager';

    /**
     * When using secrets manager, you can optionally provide a JSON key to include only a specific JSON property from
     * that secret.
     */
    key?: string;
}

interface EnvironmentVariable {
    name: string;
    value: pulumi.Input<string>;
}

/**
 * A custom type for container definitions. It removes some properties that aren't relevant for Fargate tasks and
 * enhances others for easier use in Pulumi code
 */
export interface FargateContainerDefinition
    extends Omit<
        aws.ecs.ContainerDefinition,
        | 'secrets'
        | 'environment'
        | 'logConfiguration'
        | 'dockerSecurityOptions'
        | 'hostname'
        | 'links'
        | 'repositoryCredentials'
    > {
    /**
     * An array of Secrets Manager or Parameter Store ARNs to pass to the task as environment variables.
     */
    secrets?: SecretFromInput[];

    /**
     * An array of Environment Variables to pass to the container
     */
    environment?: EnvironmentVariable[];

    /**
     * The name of an existing CloudWatch Log Group to stream logs from this container to
     */
    logGroupName?: pulumi.Input<string>;

    /**
     * The full ARN to a secret in AWS Secrets Manager containing the relevant credentials for authenticating to the
     * docker registry containing this container's image.
     *
     * https://docs.aws.amazon.com/AmazonECS/latest/developerguide/private-auth.html
     */
    repositoryCredentialsArn?: pulumi.Input<string>;
}

interface ServiceAlbConfiguration {
    /**
     * ALB Healthcheck configuration
     */
    healthCheckConfig?: aws.types.input.lb.TargetGroupHealthCheck;

    /**
     * ARN of an ALB listener to use for this service. A rule will be created to route relevant requests to the service
     *
     * Eg `arn:aws:elasticloadbalancing:<AWS_REGION>:<ACCOUNT_ID>:listener/app/name-of-alb/24cc901288efd990/eacc674b53cedc2d`
     */
    listenerArn: pulumi.Input<string>;

    /**
     * Additional actions to add to the listener rule created by this service. These actions will be performed prior to
     * the final `forward` action that sends requests to the service's target group. This is useful when you want to
     * require that requests are first authenticated via Cognito or another OpenID Connect provider prior to being
     * served to your service.
     */
    ruleActions?: Omit<aws.types.input.lb.ListenerRuleAction, 'order'>[];

    /**
     * Priority for the listener rule. Use this to ensure the rule created for this service won't clash with any
     * existing rules on the listener. Must be a positive number between 1 and 50,000 (inclusive). If the listener will
     * only contain this rule, you can leave this undefined and the resulting rule will be given the next available
     * priority on creation. Rules are evaluated in ascending order (lowest to highest)
     */
    rulePriority?: number;

    /**
     * Which port on which container (by name) should the ALB route incoming traffic to
     */
    portMapping: Omit<aws.types.input.ecs.ServiceLoadBalancer, 'targetGroupArn' | 'elbName'>;

    /**
     * ID of a Security Group that contains the ALB that will be handling traffic for this service.
     *
     * Eg `sg-9879a8e7dacd`
     */
    securityGroupId: pulumi.Input<string>;
}

type ScalableMetricType =
    | 'ALBRequestCountPerTarget'
    | 'ECSServiceAverageCPUUtilization'
    | 'ECSServiceAverageMemoryUtilization';

interface AutoScalingConfiguration {
    /**
     * The minimum number of tasks that should be running in this service. Auto-scaling will never reduce the amount of
     * running tasks to less than this number.
     */
    minTasks: number;

    /**
     * The maximum number of tasks that should be running in this service. Auto-scaling will never increase the amount
     * of running tasks to more than this number.
     */
    maxTasks: number;

    /**
     * How long (in seconds) the auto-scaling service should wait in between consecutive scale-in actions.
     *
     * Default: `60`
     */
    scaleInCooldown?: number;

    /**
     * How long (in seconds) the auto-scaling service should wait in between consecutive scale-out actions. This should
     * ideally be set to an amount of time that allows for new tasks to boot up, become healthy and start having an
     * impact on whatever metric the policy scales on (eg CPUUtilization).
     *
     * Default: `60`
     */
    scaleOutCooldown?: number;

    /**
     * What metric to use to make scaling decisions with.
     */
    scalableMetric: ScalableMetricType;

    /**
     * What value auto-scaling should attempt to keep the scalable metric at. For example if you have specified
     * 'ECSServiceAverageCPUUtilization' as the scalable metric, the threshold is what CPU Utilization you want to stay
     * under.
     */
    threshold: number;
}

export interface FargateServiceArgs {
    /**
     * Configuration needed to integrate the service with an Application Load Balancer. If not provided, the service
     * will not receive any ingress traffic.
     */
    albConfig?: ServiceAlbConfiguration;

    /**
     * Configuration required to set up auto-scaling of the service. If not provided the service will not perform any
     * autoscaling
     */
    autoScalingConfig?: AutoScalingConfiguration;

    /**
     * Name of the ECS cluster to create the service in.
     */
    clusterName: pulumi.Input<string>;

    /**
     * An array of container definitions your service. Refer to the AWS documentation for more details on the fields
     *
     * https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html
     */
    containers: FargateContainerDefinition[];

    /**
     * Amount of CPU units to allocate to your service where 512 is equal to half of a CPU core. A much more in-depth
     * explanation on how CPU and memory allocation works can be found here:
     *
     * https://aws.amazon.com/blogs/containers/how-amazon-ecs-manages-cpu-and-memory-resources/
     *
     * Default: `256`
     */
    cpu?: number;

    /**
     * Amount of memory (in MB) to allocate to your service. A much more in-depth explanation on how CPU and memory
     * allocation works can be found here:
     *
     * https://aws.amazon.com/blogs/containers/how-amazon-ecs-manages-cpu-and-memory-resources/
     *
     * Default: `512`
     */
    memory?: number;

    /**
     * The number of tasks to run in the service. If you have configured auto scaling for this service this value is
     * only used at creation time and is ignored otherwise.
     *
     * Default: `1`
     */
    desiredCount?: number;

    /**
     * Namespace used as a prefix for resource names.
     *
     * Default: `<RESOURCE_NAME>-<STACK_NAME>`
     */
    namespace?: string;

    /**
     * An array of subnet IDs that the service should utilize. Must be subnets that are within the VPC provided in
     * `vpcId`. Ideally you should supply one subnet for each Availability Zone available in your region. The subnets
     * are assumed to be private subnets - the service will not be allocated a public IP and will need a route to a NAT
     * gateway in order to access the internet.
     *
     * Eg `[ "subnet-6e76bba91252cf919", "subnet-bbb9026a13a08b2ea" ]`
     */
    subnetIds: pulumi.Input<string[]>;

    /**
     * An IAM policy defining what AWS permissions you would like the container(s) in your service to have. Defaults to
     * having no permissions
     */
    taskPolicy?: aws.iam.PolicyDocument;

    /**
     * ID of the VPC the service should be provisioned in.
     *
     * Eg `vpc-1aa478ffc`
     */
    vpcId: pulumi.Input<string>;
}

export interface FargateServiceDefaults {
    cpu: number;
    memory: number;
    desiredCount: number;
    namespace: string;
}

type Overwrite<T, U> = Pick<T, Exclude<keyof T, keyof U>> & U;

export type FargateServiceArgsWithDefaults = Overwrite<FargateServiceArgs, FargateServiceDefaults>;
