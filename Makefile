.PHONY:

COMMIT=$(shell git rev-parse HEAD)

# gather options for tests
TESTARGS=$(TESTOPTIONS)

# gather options for coverage
COVERAGEARGS=$(COVERAGEOPTIONS)

update-deps:
		glide update

test: test-cleanup test-bip32util test-wallet
test-race: test-race-bip32util test-race-wallet

test-cleanup: test-cleanup-coverage test-cleanup-profile

test-cleanup-coverage:
	rm -rf coverage/ 2>> /dev/null; \
	mkdir coverage/

test-cleanup-profile:
	rm -rf profile/ 2>> /dev/null; \
	mkdir profile/

test-bip32util:
		go test -coverprofile=coverage/bip32util.out -v \
		github.com/btccom/btcsigner/bip32util           \
		$(TESTARGS)

test-race-bip32util:
		go test -race -v                                \
		github.com/btccom/btcsigner/bip32util           \
		$(TESTARGS)

test-wallet:
		go test -coverprofile=coverage/wallet.out -v    \
		github.com/btccom/btcsigner/wallet              \
		$(TESTARGS)

test-race-wallet:
		go test -race -v                                \
		github.com/btccom/btcsigner/wallet              \
		$(TESTARGS)

# concat all coverage reports together
coverage-concat:
	echo "mode: set" > coverage/full && \
    grep -h -v "^mode:" coverage/*.out >> coverage/full

# full coverage report
coverage: coverage-concat
	go tool cover -func=coverage/full $(COVERAGEARGS)

# full coverage report
coverage-html: coverage-concat
	go tool cover -html=coverage/full $(COVERAGEARGS)

minimum-coverage: coverage-concat
	./tools/minimum-coverage.sh 45

prebuild:
