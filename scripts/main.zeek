module cotp;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:           time    &log;
        uid:          string  &log;
        id:           conn_id &log;
        bytes_orig:   count &log &default=0;
        bytes_resp:   count &log &default=0;
        packets_orig: count &log &default=0;
        packets_resp: count &log &default=0;
        calling_tsap: string  &log &optional;
        called_tsap:  string  &log &optional;
        class:        count   &log &default=0;
        has_connect:  bool    &log &default=F;
        has_disconnect: bool    &log &default=F;
        error:        bool    &log &default=F;
        reject_cause: count   &log &default=0;
    };

    global log_cotp: event(rec: Info);
}

redef record connection += {
    cotp_info: Info &optional;
};

event zeek_init() &priority=5 {
    Log::create_stream(cotp::LOG, [$columns = Info, $ev = log_cotp, $path="cotp-conn"]);
}

function get_info(c: connection): Info {
    if(!c?$cotp_info) {
        c$cotp_info = [
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
        ];
    }
    return c$cotp_info;
}

event connection_request(c: connection, is_orig: bool, calling: string, called: string, class: count) {

    local info = get_info(c);

    info$has_connect = T;
    info$class = class;
    if (!info?$calling_tsap) info$calling_tsap = calling;
    if (!info?$called_tsap) info$called_tsap = called;

}

event connection_confirm(c: connection, is_orig: bool, calling: string, called: string, class: count) {
    local info = get_info(c);

    info$class = class;
    info$has_connect = T;
    if (!info?$calling_tsap) info$calling_tsap = calling;
    if (!info?$called_tsap) info$called_tsap = called;
}

event disconnect_request(c: connection, is_orig: bool, calling: string, called: string, class: count) {
    local info = get_info(c);
    info$has_disconnect = T;
}

event disconnect_confirm(c: connection, is_orig: bool, calling: string, called: string, class: count) {
    local info = get_info(c);
    info$has_disconnect = T;
}

event data(c: connection, is_orig: bool, calling: string, called: string, class: count, user_data: string, eot: bool, expedited: bool) {
    local info = get_info(c);

    if(is_orig) {
        info$bytes_orig += |user_data|;
        info$packets_orig += 1;
    } else {
        info$bytes_resp += |user_data|;
        info$packets_resp += 1;
    }

}

event error(c: connection, is_orig: bool, calling: string, called: string, class: count, reject_cause: count) {
    local info = get_info(c);

    info$error = T;
    info$reject_cause = reject_cause;
}

event connection_state_remove(c: connection) {
    if ( c?$cotp_info ) {
        Log::write(LOG, c$cotp_info);
        delete c$cotp_info;
    }
}
