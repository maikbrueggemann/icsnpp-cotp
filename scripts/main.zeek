module cotp;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts_start:     time    &log;
        ts_end:       time    &log;
        uid:          string  &log;
        id:           conn_id &log;
        calling_tsap: string  &log;
        called_tsap:  string  &log;
        class:        count   &log;
        has_connect:      bool    &log;
        has_disconnect:   bool    &log;
        data_pkts:    count   &log;
        data_bytes:   count   &log;
        error:        bool    &log;
        reject_cause: count   &log;
    };

    global log_cotp: event(rec: Info);
}

redef record connection += {
    cotp_state: Info &optional;
};

event zeek_init() &priority=5 {
    Log::create_stream(cotp::LOG, [$columns = Info, $ev = log_cotp, $path="cotp-conn"]);
}

function create_info(
    c: connection,
    calling: string,
    called: string,
    class: count,
    ts: time,
    has_connect: bool,
    has_disconnect: bool,
    data_pkts: count,
    data_bytes: count,
    error: bool,
    reject_cause: count
): Info
{
    return [$ts_start=ts, $ts_end=ts, $uid=c$uid, $id=c$id,
            $calling_tsap=calling, $called_tsap=called, $class=class,
            $has_connect=has_connect, $has_disconnect=has_disconnect,
            $data_pkts=data_pkts, $data_bytes=data_bytes, $error=error,
            $reject_cause=reject_cause];
}

event connection_request(c: connection, is_orig: bool, calling: string, called: string, class: count) {
    local now = network_time();
    if ( ! c?$cotp_state )
        c$cotp_state = create_info(c, calling, called, class, now, T, F, 0, 0, F, 0);
    else {
        c$cotp_state$ts_end = now;
        c$cotp_state$has_connect = T;
        if ( c$cotp_state$calling_tsap == "" ) c$cotp_state$calling_tsap = calling;
        if ( c$cotp_state$called_tsap == "" ) c$cotp_state$called_tsap = called;
        c$cotp_state$class = class;
    }
}

event connection_confirm(c: connection, is_orig: bool, calling: string, called: string, class: count) {
    local now = network_time();
    if ( ! c?$cotp_state )
        c$cotp_state = create_info(c, calling, called, class, now, F, F, 0, 0, F, 0);
    else {
        c$cotp_state$ts_end = now;
        if ( c$cotp_state?$calling_tsap ) c$cotp_state$calling_tsap = calling;
        if ( c$cotp_state?$called_tsap ) c$cotp_state$called_tsap = called;
        c$cotp_state$class = class;
    }
}

event disconnect_request(c: connection, is_orig: bool, calling: string, called: string, class: count) {
    local now = network_time();
    if ( ! c?$cotp_state )
        c$cotp_state = create_info(c, calling, called, class, now, F, T, 0, 0, F, 0);
    else {
        c$cotp_state$ts_end = now;
        c$cotp_state$has_disconnect = T;
        if ( c$cotp_state?$calling_tsap ) c$cotp_state$calling_tsap = calling;
        if ( c$cotp_state?$called_tsap ) c$cotp_state$called_tsap = called;
        c$cotp_state$class = class;
    }
}

event disconnect_confirm(c: connection, is_orig: bool, calling: string, called: string, class: count) {
    local now = network_time();
    if ( ! c?$cotp_state )
        c$cotp_state = create_info(c, calling, called, class, now, F, T, 0, 0, F, 0);
    else {
        c$cotp_state$ts_end = now;
        c$cotp_state$has_disconnect = T;
        if ( c$cotp_state?$calling_tsap ) c$cotp_state$calling_tsap = calling;
        if ( c$cotp_state?$called_tsap ) c$cotp_state$called_tsap = called;
        c$cotp_state$class = class;
    }
}

event data(c: connection, is_orig: bool, calling: string, called: string, class: count, user_data: string, eot: bool, expedited: bool) {
    local now = network_time();
    if ( ! c?$cotp_state )
        c$cotp_state = create_info(c, calling, called, class, now, F, F, 1, |user_data|, F, 0);
    else {
        c$cotp_state$ts_end = now;
        if ( eot ) c$cotp_state$data_pkts += 1;
        c$cotp_state$data_bytes += |user_data|;
        if ( c$cotp_state?$calling_tsap ) c$cotp_state$calling_tsap = calling;
        if ( c$cotp_state?$called_tsap ) c$cotp_state$called_tsap = called;
        c$cotp_state$class = class;
    }
}

event error(c: connection, is_orig: bool, calling: string, called: string, class: count, reject_cause: count) {
    local now = network_time();
    if ( ! c?$cotp_state )
        c$cotp_state = create_info(c, calling, called, class, now, F, F, 0, 0, T, reject_cause);
    else {
        c$cotp_state$ts_end = now;
        c$cotp_state$error = T;
        c$cotp_state$reject_cause = reject_cause;
    }
}

event connection_state_remove(c: connection) {
    if ( c?$cotp_state ) {
        Log::write(LOG, c$cotp_state);
        delete c$cotp_state;
    }
}
