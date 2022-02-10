DB := example
IPYTHON := no
WAREHOUSE_CLI := docker-compose run --rm web python -m warehouse

# set environment variable WAREHOUSE_IPYTHON_SHELL=1 if IPython
# needed in development environment
ifeq ($(WAREHOUSE_IPYTHON_SHELL), 1)
    IPYTHON = yes
endif

default:
	@echo "Call a specific subcommand:"
	@echo
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null\
	| awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}'\
	| sort\
	| egrep -v -e '^[^[:alnum:]]' -e '^$@$$'
	@echo
	@exit 1

.state/docker-build: Dockerfile package.json package-lock.json requirements/main.txt requirements/deploy.txt
	# Build our docker containers for this project.
	docker-compose build --build-arg IPYTHON=$(IPYTHON) --force-rm web
	docker-compose build --force-rm worker
	docker-compose build --force-rm static

	# Mark the state so we don't rebuild this needlessly.
	mkdir -p .state
	touch .state/docker-build

build:
	@$(MAKE) .state/docker-build

	docker system prune -f --filter "label=com.docker.compose.project=warehouse"

serve: .state/docker-build
	docker-compose up --remove-orphans

debug: .state/docker-build
	docker-compose run --rm --service-ports web

tests: .state/docker-build
	docker-compose run --rm web bin/tests --postgresql-host db $(T) $(TESTARGS)

static_tests: .state/docker-build
	docker-compose run --rm static bin/static_tests $(T) $(TESTARGS)

static_pipeline: .state/docker-build
	docker-compose run --rm static bin/static_pipeline $(T) $(TESTARGS)

reformat: .state/docker-build
	docker-compose run --rm web bin/reformat

lint: .state/docker-build
	docker-compose run --rm web bin/lint && bin/static_lint

docs: .state/docker-build
	docker-compose run --rm web bin/docs

licenses: .state/docker-build
	docker-compose run --rm web bin/licenses

deps: .state/docker-build
	docker-compose run --rm web bin/deps

translations: .state/docker-build
	docker-compose run --rm web bin/translations

requirements/%.txt: requirements/%.in
	docker-compose run --rm web bin/pip-compile --allow-unsafe --generate-hashes --output-file=$@ $<

initdb:
	docker-compose run --rm web psql -h db -d postgres -U postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname ='warehouse';"
	docker-compose run --rm web psql -h db -d postgres -U postgres -c "DROP DATABASE IF EXISTS warehouse"
	docker-compose run --rm web psql -h db -d postgres -U postgres -c "CREATE DATABASE warehouse ENCODING 'UTF8'"
	xz -d -f -k dev/$(DB).sql.xz --stdout | docker-compose run --rm web psql -h db -d warehouse -U postgres -v ON_ERROR_STOP=1 -1 -f -
	docker-compose run --rm web python -m warehouse db upgrade head
	$(MAKE) reindex
	docker-compose run web python -m warehouse sponsors populate-db

inittuf:
	$(WAREHOUSE_CLI) tuf dev keypair --name root --path /opt/warehouse/src/dev/tufkeys/root
	$(WAREHOUSE_CLI) tuf dev keypair --name snapshot --path /opt/warehouse/src/dev/tufkeys/snapshot
	$(WAREHOUSE_CLI) tuf dev keypair --name targets --path /opt/warehouse/src/dev/tufkeys/targets
	$(WAREHOUSE_CLI) tuf dev keypair --name timestamp --path /opt/warehouse/src/dev/tufkeys/timestamp
	$(WAREHOUSE_CLI) tuf dev keypair --name bins --path /opt/warehouse/src/dev/tufkeys/bins
	$(WAREHOUSE_CLI) tuf dev keypair --name bin-n --path /opt/warehouse/src/dev/tufkeys/bin-n
	$(WAREHOUSE_CLI) tuf dev new-repo
	$(WAREHOUSE_CLI) tuf admin delegate-targets-roles
	$(WAREHOUSE_CLI) tuf dev add-targets

reindex:
	docker-compose run --rm web python -m warehouse search reindex

shell:
	docker-compose run --rm web python -m warehouse shell

clean:
	rm -rf dev/*.sql
	rm -rf dev/tufkeys

purge: stop clean
	rm -rf .state
	docker-compose rm --force

stop:
	docker-compose down -v

.PHONY: default build serve initdb shell tests docs deps clean purge debug stop compile-pot
