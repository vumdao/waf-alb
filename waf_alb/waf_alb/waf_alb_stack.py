from aws_cdk import (
    aws_cloudformation as cfn,
    aws_wafv2 as waf,
    core,
)


class WafStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, env, target_arn, **kwargs) -> None:
        super().__init__(scope, id, env=env, **kwargs)

        waf_rules = list()

        """ 1. Reputation List """
        aws_ip_rep_list = waf.CfnWebACL.RuleProperty(
            name='WafIpreputation',
            priority=1,
            override_action=waf.CfnWebACL.OverrideActionProperty(count={}),
            statement=waf.CfnWebACL.StatementOneProperty(
                managed_rule_group_statement=waf.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name='AWSManagedRulesAmazonIpReputationList',
                    vendor_name='AWS',
                    excluded_rules=[]
                )
            ),
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name='aws_reputation',
                sampled_requests_enabled=True,
            )
        )
        waf_rules.append(aws_ip_rep_list)

        """ 2. AnonymousIpList """
        aws_anony_list = waf.CfnWebACL.RuleProperty(
            name='WafAnony',
            priority=2,
            override_action=waf.CfnWebACL.OverrideActionProperty(count={}),
            statement=waf.CfnWebACL.StatementOneProperty(
                managed_rule_group_statement=waf.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name='AWSManagedRulesAnonymousIpList',
                    vendor_name='AWS',
                    excluded_rules=[]
                )
            ),
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name='aws_anony',
                sampled_requests_enabled=True,
            )
        )
        waf_rules.append(aws_anony_list)

        """ 3. CommonRule """
        aws_common_rule = waf.CfnWebACL.RuleProperty(
            name='WafCommonRule',
            priority=3,
            override_action=waf.CfnWebACL.OverrideActionProperty(count={}),
            statement=waf.CfnWebACL.StatementOneProperty(
                managed_rule_group_statement=waf.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name='AWSManagedRulesCommonRuleSet',
                    vendor_name='AWS',
                    excluded_rules=[]
                )
            ),
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name='aws_common',
                sampled_requests_enabled=True,
            )
        )
        waf_rules.append(aws_common_rule)

        """ 4. PHP Rule """
        aws_php_rule = waf.CfnWebACL.RuleProperty(
            name='WafPHPRule',
            priority=4,
            override_action=waf.CfnWebACL.OverrideActionProperty(count={}),
            statement=waf.CfnWebACL.StatementOneProperty(
                managed_rule_group_statement=waf.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name='AWSManagedRulesPHPRuleSet',
                    vendor_name='AWS',
                    excluded_rules=[]
                )
            ),
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name='aws_php',
                sampled_requests_enabled=True,
            )
        )
        waf_rules.append(aws_php_rule)

        """ 5. Linux Rule """
        aws_linux_rule = waf.CfnWebACL.RuleProperty(
            name='WafLinuxRule',
            priority=5,
            override_action=waf.CfnWebACL.OverrideActionProperty(count={}),
            statement=waf.CfnWebACL.StatementOneProperty(
                managed_rule_group_statement=waf.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name='AWSManagedRulesLinuxRuleSet',
                    vendor_name='AWS',
                    excluded_rules=[]
                )
            ),
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name='aws_linux',
                sampled_requests_enabled=True,
            )
        )
        waf_rules.append(aws_linux_rule)

        """ DefaultAction: Action of AWS WAF to perform when a web request doesn't match any of the rules in the WebACL. """
        web_acl = waf.CfnWebACL(
            self, 'WebACL',
            default_action=waf.CfnWebACL.DefaultActionProperty(
                allow={}
            ),
            scope="REGIONAL",  # vs 'CLOUDFRONT'
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name='webACL',
                sampled_requests_enabled=True
            ),
            name=f'prod-acl',
            rules=waf_rules
        )

        """ Associate it with the resource provided. """
        waf.CfnWebACLAssociation(self, 'WAFACLAssociateALB',
                                 web_acl_arn=web_acl.attr_arn,
                                 resource_arn=target_arn
                                 )

