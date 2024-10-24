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

      `debug` is used to verbose mode.

      `expected_receive_period_in_days` is used to determine if the Agent is working. Set it to the maximum number of days
      that you anticipate passing without this Agent receiving an incoming Event.
      MD
    end

    event_description <<-MD
      Events look like this:

          {
             "id": 53621004,
             "details_url": "https://developer.mozilla.org/en-US/observatory/analyze?host=callistodao.org",
             "algorithm_version": 4,
             "scanned_at": "2024-10-22T22:53:21.572Z",
             "error": null,
             "grade": "D",
             "score": 30,
             "status_code": 200,
             "tests_failed": 4,
             "tests_passed": 6,
             "tests_quantity": 10
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
    end

    def working?
      event_created_within?(options['expected_receive_period_in_days']) && !recent_error_logs?
    end

    def check
      check_status
    end

    private

    def check_site()
      uri = URI.parse("https://observatory-api.mdn.mozilla.net/api/v2/scan?host=#{interpolated['site']}")
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

      if payload['error'] == 'database-down'
        error("Unable to connect to database")
      else
        return payload
      end
    end

    def check_status()
      payload = check_site()
      if interpolated['debug'] == 'true'
        log payload['status_code']
      end
      while payload['status_code'] != 200
        sleep(30)
        payload = check_site()
      end
      if interpolated['changes_only'] == 'true'
        if payload != memory['last_status']
          if !memory['last_status'].nil?
            last_status = memory['last_status']
            if payload['score'] != last_status['score'] && payload['status_code'] == 200
              create_event payload: payload
            else
              log "no diff"
            end
          else
            if payload['status_code'] == 200
              create_event payload: payload
            end
          end
          memory['last_status'] = payload
        end
      else
        create_event payload: payload
        if payload.to_s != memory['last_status']
          memory['last_status'] = payload
        end
      end
    end
  end
end
