# Template code for reading formatted text and converting it into events.
#
@load base/protocols/ssh
@load frameworks/communication/listen
@load base/frameworks/input

module IN_STREAM_TEMPLATE;

export {

	redef enum Notice::Type += {
	INPUT_DataReset,
        INPUT_LowTransactionRate,
        INPUT_HighTransactionRate,
		};

	## table holding map between event name -> processing function
	const dispatcher: table[string] of function(_data: string): count &redef;
	# location of input file this should be changed
	const data_file = "/" &redef;
	# flag to make the current node active re the input framework
	#  it is activated by setting 'aux_scripts="isshd_policy/init_node"'
	#  in the etc/node.cfg .  See the isshd_policy/init_node.bro for
	#  more details.
	const DATANODE = F &redef;

	# semiphore for in-fr restart
	global stop_sem = 0;

	# track the transaction rate - notice on transition between low and high water rates
	# this is count per input_test_interval
	const input_count_test = T &redef;
	const input_low_water:count = 10 &redef;
	const input_high_water:count = 10000 &redef;
	const input_test_interval:interval = 60 sec &redef;
	# track input rate ( events/input_test_interval)
	global input_count: count = 1 &redef;
	global input_count_prev: count = 1 &redef;
	global input_count_delta: count = 0 &redef;
	#  0=pre-init, 1=ok, 2=in low error
	global input_count_state: count = 0 &redef;

	}

type lineVals: record {
	d: string;
};

redef InputAscii::empty_field = "EMPTY";

## ----- functions ----- ##
#
function ssh_time(s: string) : time
	{
	# default return value is 0.00000 which is the error token
	local key_val = split_string1(s, /=/);
	local ret_val: time = double_to_time( to_double("0.000000"));

	if ( |key_val| == 2 ) {

		local mpr = match_pattern( key_val[1], time_match);

		if ( mpr$matched )
			ret_val = double_to_time( to_double(key_val[1] ));

		}

	return ret_val;
	}

function _text-processing-function-name(_data: string) : count
	{
    # do stuff with the data
	return 0;
	}

# # #
# Dispatcher holds the mapping between a key value (event driver),
#   and the function that will parse the data and call the native event.
# # #
redef dispatcher += {
	["LITERAL-TEXT"] = _text-processing-function-name,
	};

# # #
# This event gets called for each line read by the input framework.  See init_datastream
#   for details on getting the data.
#
# description: Input::EventDescription
#    This is the name of the data stream.  Normally set at the time that the
#      input stream is initialized.
# tpe: Input::Event
#    ...
# LV: lineVals
#    Data structure defined above - see line 43.  Can be extremely simple as in This
#      case where there is a single element LV$d, or the line of raw text data.
# # #
event sshLine(description: Input::EventDescription, tpe: Input::Event, LV: lineVals)
	{
    # for example here we swap out two 0x20 hex values (i.e. two spaces) for a blank space
	local t_d = gsub(LV$d, /\x20\x20/, " ");
    # and load the squeezed set back into the LV$d data element
	LV$d = t_d;

    # split the string via some key value splitter
    local parts = split_string(LV$d, kv_splitter);
    # count the parts
	local l_parts = |parts|;
	# get the event name - this might be different depending on the structure of the data.
	local event_name = parts[0];

	# count the transaction record
	++input_count;

	# example sanity check for broken of misformed data
	if ( l_parts < 5 )
		return;

	# If the event name is in the dispatcher list - see line 82 - then the
    #   /function/ associated with that name is called with the complete raw
    #   data line as an argument.
	#
    if ( event_name !in dispatcher ) {
		dispatcher[event_name](LV$d);
        }

} # end of sshLine event


event stop_reader()
	{
	if ( stop_sem == 0 ) {
		Input::remove("template");
		stop_sem = 1;

		NOTICE([$note=INPUT_DataReset,$msg=fmt("stopping reader")]);
		}
	}

event start_reader()
	{
	if ( stop_sem == 1 ) {
		local config_strings: table[string] of string = {
			["offset"] = "-1",
			};

		Input::add_event([$source=data_file, $config=config_strings, $reader=Input::READER_RAW, $mode=Input::STREAM, $name="template", $fields=lineVals, $ev=sshLine]);
		stop_sem = 0;

		NOTICE([$note=INPUT_DataReset,$msg=fmt("starting reader")]);
		}
	}

event transaction_rate()
	{
	# Values for input_count_state:
	#  0=pre-init, 1=ok, 2=in error
	# We make the assumption here that the low_water < high_water
	# Use a global for input_count_delta so that the value is consistent across
	#   anybody looking at it.
	input_count_delta = input_count - input_count_prev;
	#print fmt("%s Log delta: %s", network_time(),delta);

	# rate is too low - send a notice the first time
	if (input_count_delta <= input_low_water) {

		# only send the notice on the first instance
		if ( input_count_state != 2 ) {
			NOTICE([$note=INPUT_LowTransactionRate,
				$msg=fmt("event rate %s per %s", input_count_delta, input_test_interval)]);

			input_count_state = 2; # 2: transaction rate
			}

		# Now reset the reader by scheduling a stop() call, waiting long
        #   enough for the cluster to hear, then start up again.
		schedule 1 sec { stop_reader() };
		schedule 10 sec { start_reader() };
		}

	# rate is too high - send a notice the first time
	if (input_count_delta >= input_high_water) {

		# only send the notice on the first instance
		if ( input_count_state != 2 ) {
			NOTICE([$note=INPUT_HighTransactionRate,
				$msg=fmt("event rate %s per %s", input_count_delta, input_test_interval)]);

			input_count_state = 2; # 2: transaction rate
			}
		}

	# rate is ok
	if ( (input_count_delta > input_low_water) && (input_count_delta < input_high_water) ) {
		input_count_state = 1;
		}

	# rotate values
	input_count_prev = input_count;

	# reschedule this all over again ...
	schedule input_test_interval { transaction_rate() };
	}

function init_datastream() : count
	{
	# input stream setup
	if ( DATANODE && (file_size(data_file) != -1.0) ) {
		print fmt("%s data file %s located", gethostname(), data_file);

		local config_strings: table[string] of string = {
			["offset"] = "-1",
			};

		Input::add_event([$source=data_file, $config=config_strings, $reader=Input::READER_RAW, $mode=Input::STREAM, $name="template", $fields=lineVals, $ev=sshLine]);

		# start rate monitoring for event stream
		schedule input_test_interval { transaction_rate() };
		}

	return 0;
	}

event bro_init()
	{
	init_datastream();
	}
