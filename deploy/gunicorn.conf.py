"""Bounded production WSGI configuration for the orchestrator API."""

import os


bind = os.getenv("ORCHESTRATOR_BIND", "127.0.0.1:8080")
workers = int(os.getenv("ORCHESTRATOR_WEB_WORKERS", "2"))
threads = int(os.getenv("ORCHESTRATOR_WEB_THREADS", "4"))
worker_class = "gthread"
timeout = int(os.getenv("ORCHESTRATOR_REQUEST_TIMEOUT", "60"))
graceful_timeout = 30
keepalive = 5
max_requests = 2000
max_requests_jitter = 200
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("ORCHESTRATOR_LOG_LEVEL", "info")
capture_output = True
forwarded_allow_ips = ""
limit_request_line = 4094
limit_request_fields = 80
limit_request_field_size = 8190
