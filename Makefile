# Thin wrapper: every target runs scripts/tasks.sh, so `sh scripts/tasks.sh <target>` is identical.
.PHONY: validate-seeds env up down test eval demo-fixtures logs qr ps check-secrets export-workflows build-workflows reload-workflows security demo
validate-seeds env up down test eval demo-fixtures logs qr ps check-secrets export-workflows build-workflows reload-workflows security demo:
	sh scripts/tasks.sh $@
