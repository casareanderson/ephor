"""Ephor — a passive, dependency-light monitor for what AI agents do on a Linux box.

No proxy, no agent, no daemon-in-your-traffic: it reads /proc and the socket table, attributes every outbound
connection to the agent that made it, records where each agent went and how much it pulled down, flags
known-bad destinations against public threat feeds, and shows what each agent can actually access. Detect-only.
"""
__version__ = "0.1.0"
