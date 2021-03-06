#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_verisign'


class Whois
  class Parsers

    # Parser for the ccwhois.verisign-grs.com server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class CcwhoisVerisignGrsCom < BaseVerisign
    end

  end
end
