#!/usr/bin/env python3
"""
Test script to run the web monitoring interface for timeline testing
"""

import sys
import os
sys.path.append('coordinator')

from coordinator.monitoring_web import run_web_interface

if __name__ == "__main__":
    print("Starting SOC Blackboard Web Monitor...")
    print("Timeline test URL: http://localhost:5000/investigation/3052")
    run_web_interface(host='127.0.0.1', port=5000, debug=True)