module Agents
  class HttpObservatoryMozillaAgent < Agent
    include FormConfigurable
    can_dry_run!
    no_bulk_receive!
    default_schedule 'every_1d'

    description do
      <<-MD
      The Http Observatory Mozilla Agent is used to test the state of security for websites on the public internet with Mozilla API.

      `site` wanted hostname.

      `hidden` setting to "true" will hide a scan from public results returned by getRecentScans.

      `rescan` setting to "true" forces a rescan of a site.

      `debug` is used to verbose mode.

      `expected_receive_period_in_days` is used to determine if the Agent is working. Set it to the maximum number of days
      that you anticipate passing without this Agent receiving an incoming Event.
      MD
    end

    event_description <<-MD
      Events look like this:

          {
            "algorithm_version": 2,
            "end_time": "Wed, 15 Jun 2022 19:07:19 GMT",
            "grade": "B-",
            "hidden": false,
            "likelihood_indicator": "MEDIUM",
            "response_headers": {
              "Cache-Control": "max-age=0, private, must-revalidate",
              "Content-Type": "text/html; charset=utf-8",
              "Date": "Wed, 15 Jun 2022 19:07:17 GMT",
              "Etag": "W/\"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\"",
              "Referrer-Policy": "strict-origin-when-cross-origin",
              "Set-Cookie": "_rails_session=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX; path=/; HttpOnly",
              "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
              "Transfer-Encoding": "chunked",
              "Vary": "Origin",
              "X-Content-Type-Options": "nosniff",
              "X-Download-Options": "noopen",
              "X-Frame-Options": "DENY",
              "X-Permitted-Cross-Domain-Policies": "none",
              "X-Request-Id": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
              "X-Runtime": "0.011662",
              "X-Xss-Protection": "1; mode=block"
            },
            "scan_id": 27190361,
            "score": 65,
            "start_time": "Wed, 15 Jun 2022 19:07:15 GMT",
            "state": "FINISHED",
            "status_code": 200,
            "tests_failed": 2,
            "tests_passed": 10,
            "tests_quantity": 12
          }
    MD

    def default_options
      {
        'debug' => 'false',
        'expected_receive_period_in_days' => '2',
        'hidden' => 'false',
        'rescan' => 'false',
        'changes_only' => 'true'
      }
    end

    form_configurable :expected_receive_period_in_days, type: :string
    form_configurable :site, type: :string
    form_configurable :changes_only, type: :boolean
    form_configurable :debug, type: :boolean
    form_configurable :hidden, type: :boolean
    form_configurable :rescan, type: :boolean

    def validate_options
      if options.has_key?('changes_only') && boolify(options['changes_only']).nil?
        errors.add(:base, "if provided, changes_only must be true or false")
      end

      if options.has_key?('debug') && boolify(options['debug']).nil?
        errors.add(:base, "if provided, debug must be true or false")
      end

      unless options['expected_receive_period_in_days'].present? && options['expected_receive_period_in_days'].to_i > 0
        errors.add(:base, "Please provide 'expected_receive_period_in_days' to indicate how many days can pass before this Agent is considered to be not working")
      end

      if options.has_key?('hidden') && boolify(options['hidden']).nil?
        errors.add(:base, "if provided, hidden must be true or false")
      end

      if options.has_key?('rescan') && boolify(options['rescan']).nil?
        errors.add(:base, "if provided, rescan must be true or false")
      end
    end

    def working?
      event_created_within?(options['expected_receive_period_in_days']) && !recent_error_logs?
    end

    def check
      check_status
    end

    private

    def check_site()
      uri = URI.parse("https://http-observatory.security.mozilla.org/api/v1/analyze?host=#{interpolated['site']}&hidden=#{interpolated['hidden']}&rescan=#{interpolated['rescan']}")
      request = Net::HTTP::Post.new(uri)
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log "request  status : #{response.code}"

      payload = JSON.parse(response.body)

      if interpolated['debug'] == 'true'
        log payload
      end
      return payload
    end

    def check_status()
      payload = check_site()
      if interpolated['debug'] == 'true'
        log payload['state']
      end
      if payload['state'] == 'PENDING'
        sleep(30)
        payload = check_site()
      end
      if interpolated['changes_only'] == 'true'
        if payload.to_s != memory['last_status']
          if !memory['last_status'].nil?
            last_status = memory['last_status'].gsub("=>", ": ").gsub(": nil", ": null")
            last_status = JSON.parse(last_status)
            if payload['score'] != last_status['score'] && payload['status_code'] == 200
              create_event payload: payload
            end
          else
            if payload['status_code'] == 200
              create_event payload: payload
            end
          end
          memory['last_status'] = payload.to_s
        end
      else
        create_event payload: payload
        if payload.to_s != memory['last_status']
          memory['last_status'] = payload.to_s
        end
      end
    end
  end
end
