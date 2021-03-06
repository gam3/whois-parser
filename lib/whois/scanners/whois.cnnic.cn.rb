require_relative 'base'

class Whois
  module Scanners

    # Scanner for the whois.cnnic.cn record.
    class WhoisCnnicCn < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_reserved,
          :scan_reserved_list,
          :scan_available,
          :scan_keyvalue,
      ]


      tokenizer :scan_available do
        if @input.match?(/^no matching record/)
          @ast["status:available"] = true
          @input.scan_until(/\n/)
        end
      end

      tokenizer :scan_reserved do
        if @input.match?(/^The domain you requested is prohibited/)
          @ast["status:reserved"] = true
          @input.scan_until(/\n/)
        end
      end

      tokenizer :scan_reserved_list do
        if @input.scan(/^Sorry, The domain you requested is in the reserved list/)
          @ast["status:reserved"] = true
          @input.scan_until(/\n/)
        end
      end

    end

  end
end
