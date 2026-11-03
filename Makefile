# Thin wrapper: every target runs scripts/tasks.sh, so `sh scripts/tasks.sh <target>` is identical.
.PHONY: validate-seeds env up down test eval demo-fixtures logs qr ps check-secrets export-workflows security
validate-seeds env up down test eval demo-fixtures logs qr ps check-secrets export-workflows security:
	sh scripts/tasks.sh $@
