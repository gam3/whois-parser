#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_cocca'


class Whois
  class Parsers

    # Parser for the whois.netcom.cm server.
    class WhoisNetcomCm < BaseCocca

      self.status_mapping.merge!({
          "suspended" => :registered
      })

    end

  end
end
