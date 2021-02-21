#!/usr/bin/env python3

from aws_cdk import core

from waf_alb.waf_alb_stack import WafStack


app = core.App()
target_arn = 'arn:aws:elasticloadbalancing:eu-west-2:111111111111:loadbalancer/app/lon-vc-p-alb/67e2942dd0bd49c8'
core_env = core.Environment(region='eu-west-2')

waf_stack = WafStack(app, f"theWalACLAlb{reg}", env=core_env, target_arn=target_arn)


app.synth()
