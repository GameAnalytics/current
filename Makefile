.PHONY: clean deep-clean deps compile test

ERL=erl

R3 = ./rebar3

compile:
	$(R3) compile

deep-clean: clean
	-rm -rf rebar.lock
	-rm -rf _build
	-rm -rf log
	-rm -rf _install
	-rm -rf _rel

clean:
	$(R3) clean

deps:
	$(R3) do upgrade, tree

eunit: priv/aws_credentials.term
	$(R3) eunit

test: eunit

dialyzer:
	$(R3) dialyzer

xref:
	$(R3) xref

priv/aws_credentials.term:
	cp priv/aws_credentials.term.template priv/aws_credentials.term
