# Thin wrapper: every target runs scripts/tasks.sh, so `sh scripts/tasks.sh <target>` is identical.
.PHONY: env up down test eval demo-fixtures logs qr ps check-secrets export-workflows security
env up down test eval demo-fixtures logs qr ps check-secrets export-workflows security:
	sh scripts/tasks.sh $@
