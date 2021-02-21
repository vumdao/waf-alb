<p align="center">
  <a href="https://dev.to/vumdao">
    <img alt="Using AWS Waf And Shield To Protect DDoS" src="https://dev-to-uploads.s3.amazonaws.com/uploads/articles/q2f056d5uj1t3skwl1fe.png" width="500" />
  </a>
</p>
<h1 align="center">
  <div><b>Using AWS Waf And Shield To Protect DDoS</b></div>
</h1>

## AWS Shield and Web Application Firewall (WAF) are both products which provide perimeter defence for AWS networks.

## Shield provides DDOS protection and WAF is a Layer 7 Application Firewall.

## Ref: https://www.cloudflare.com/en-au/learning/ddos/what-is-a-ddos-attack/

## We can use CDK to create AWS WAF with the expected rules and associate it to the ALB

## What’s In This Document 
- [Init WAF CDK Project](#-Init-WAF-CDK-Project)
- [Write code stack](#-Write-code-stack)
- [Deploy stacks](#-Deploy-stacks)

### 🚀 **[Init WAF CDK Project](#-Init-WAF-CDK-Project)**
```
⚡ $ mkdir waf_alb
⚡ $ cd waf_alb
⚡ $ cdk init -l python
```
### 🚀 **[Write code stack](#-Write-code-stack)**
- At `RuleProperty`, we set `OverrideActionProperty` to `count` so that if a rule matches a web request, it only counts the match.
- To defines and enables Amazon CloudWatch metrics and web request sample collection, we enable `VisibilityConfig`
- Scope: `REGIONAL` vs `CLOUDFRONT`
    + REGIONAL: A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API
    + CLOUDFRONT

- How to get availabe managed rule group:
```
aws wafv2 list-available-managed-rule-groups --scope REGIONAL
```

- code: https://github.com/vumdao/waf-alb/waf_alb_stack.py

```
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
```

### 🚀 **[Deploy stacks](#-Deploy-stacks)**
```
⚡ $ cdk ls
theWalACLAlblon

⚡ $ cdk deploy 
theWalACLAlblon: deploying...
theWalACLAlblon: creating CloudFormation changeset...
[██████████████████████████████████████████████████████████] (4/4)


 ✅  theWalACLAlblon

Stack ARN:
arn:aws:cloudformation:eu-west-2:111111111111:stack/theWalACLAlblon/fbe06250-740f-11eb-9c9f-0685bc814060
```

- Requests:
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ducohx9p4rhj7wsquaif.png)

- Rules:
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ouz75dyj9jo72gugm3fl.png)

- Associate ALB
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/lgrmdhhgrp2mla0nztpx.png)

- Cloudwatch metrics
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/psltrd7doo9lhs8kqm70.png)

<h3 align="center">
  <a href="https://dev.to/vumdao">:stars: Blog</a>
  <span> · </span>
  <a href="https://github.com/vumdao/">Github</a>
  <span> · </span>
  <a href="https://vumdao.hashnode.dev/">Web</a>
  <span> · </span>
  <a href="https://www.linkedin.com/in/vu-dao-9280ab43/">Linkedin</a>
  <span> · </span>
  <a href="https://www.linkedin.com/groups/12488649/">Group</a>
  <span> · </span>
  <a href="https://www.facebook.com/CloudOpz-104917804863956">Page</a>
  <span> · </span>
  <a href="https://twitter.com/VuDao81124667">Twitter :stars:</a>
</h3>