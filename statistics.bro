# Author: Mao Philipp
# measure IAT stastics with zeek

module IAT;

export {
    redef enum Log::ID += { LOG };
    redef enum Log::ID += { LOG2 };
    type IATInfo: record {
        uid:	string	&log;
        id: conn_id     &log &optional;
        orig_ave_IAT:   double &log &optional;
        orig_max_IAT:   double &log &optional;
        orig_sum_IAT:   double &log &optional;
        orig_min_IAT:   double &log &optional;
        resp_ave_IAT:   double &log &optional;
        resp_max_IAT:   double &log &optional;
        resp_sum_IAT:   double &log &optional;
        resp_min_IAT:   double &log &optional;
        tot_ave_IAT:        double &log &optional;     
        tot_max_IAT:        double &log &optional;    
        tot_sum_IAT:        double &log &optional;   
        tot_min_IAT:        double &log &optional;
        orig_ave_pktsz: double &log &optional;
        orig_max_pktsz: double &log &optional;
        orig_sum_pktsz: double &log &optional;
        orig_min_pktsz: double &log &optional;
        resp_ave_pktsz_: double &log &optional;
        resp_max_pktsz: double &log &optional;
        resp_sum_pktsz: double &log &optional;
        resp_min_pktsz: double &log &optional;
        orig_tcpinitsize: count &log &optional;
    };
    global conn_list_orig: table[string] of time;
    global conn_list_resp: table[string] of time;
    global conn_list_tot: table[string] of time;
    global iat_result_list: table[string] of table[string] of vector of double;
    global pktsz_result_list: table[string] of table[string] of vector of double;
    global winsz_result_list: table[string] of count;
}

redef record Conn::Info += {
    orig_ave_IAT:   double &log &optional;
    orig_max_IAT:   double &log &optional;
    orig_sum_IAT:   double &log &optional;
    orig_min_IAT:   double &log &optional;
    resp_ave_IAT:   double &log &optional;
    resp_max_IAT:   double &log &optional;
    resp_sum_IAT:   double &log &optional;
    resp_min_IAT:   double &log &optional;
    tot_ave_IAT:        double &log &optional;     
    tot_max_IAT:        double &log &optional;    
    tot_sum_IAT:        double &log &optional;   
    tot_min_IAT:        double &log &optional;
    orig_ave_pktsz: double &log &optional;
    orig_max_pktsz: double &log &optional;
    orig_sum_pktsz: double &log &optional;
    orig_min_pktsz: double &log &optional;
    resp_ave_pktsz: double &log &optional;
    resp_max_pktsz: double &log &optional;
    resp_sum_pktsz: double &log &optional;
    resp_min_pktsz: double &log &optional;
    orig_tcpinitsize: count &log &optional;
};

function max_value(v: vector of double): double{
    if (|v| == 0){
        return 0;
    }
    local mx: double = v[0];
    for (p in v){
        if (v[p] > mx){
            mx = v[p];
        }
    }
    return mx;
}

function min_value(v: vector of double): double{
    if (|v| == 0){
        return 0;
    }
    local mx: double = v[0];
    for (p in v){
        if (v[p] < mx){
            mx = v[p];
        }
    }
    return mx;
}

function sum_value(v: vector of double): double{
    if (|v| == 0){
        return 0;
    }
    local mx: double = 0.0;
    for (p in v){
        mx += v[p];
    }
    return mx;
}

function avg_value(v: vector of double): double{
    if (|v| == 0){
        return 0;
    }
    local mx: double = sum_value(v);
    local vx: double = mx/|v|;
    return vx;
}

function merge_vectors(v1: vector of double, v2: vector of double): vector of double{
    local mx: vector of double = copy(v2);
    for (p in v1){
        mx[|mx|] = v1[p];
    }
    return mx;
}

function len_value(v: vector of double): count{
    return |v|;
}

event bro_init() {
    Log::create_stream(IAT::LOG, [$columns=IATInfo, $path="iat"]);
}

event connection_SYN_packet(c: connection, pkt: SYN_packet){
    # get tcp init window number
    local size: count = pkt$win_size;
    local scale: int = pkt$win_scale;
    if (scale != -1) {
        size = size * scale;
    }
    winsz_result_list[c$uid] = size;
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) &priority=-5 {
    # check if table entry for connection uid already exists
    local rnr = c$uid in iat_result_list;
    local rnr2 = c$uid in pktsz_result_list;
    if ( ! rnr) {
        iat_result_list[c$uid] = table(["orig"] = vector(), ["resp"] = vector(), ["tot"] = vector());
    }
    if ( ! rnr2) {
        pktsz_result_list[c$uid] = table(["orig"] = vector(), ["resp"] = vector());
    }
    if ( ! is_orig ) {
        # IAT 
	    if ( c$uid in conn_list_orig ) {
            local tto: double = |network_time() - conn_list_orig[c$uid]|;
            local vco: vector of double = iat_result_list[c$uid]["orig"];
            vco[|vco|] = tto;
            iat_result_list[c$uid]["orig"] = vco;
	    }
	    conn_list_orig[c$uid] = network_time();
        # pktsize
        local pkts: double = len;
        local vpkts: vector of double = pktsz_result_list[c$uid]["orig"];
        vpkts[|vpkts|] = pkts;
        pktsz_result_list[c$uid]["orig"] = vpkts;
    }
    if ( is_orig ) {
        if ( c$uid in conn_list_resp ) {
            local tt: double = |network_time() - conn_list_resp[c$uid]|;
            local vcr: vector of double = iat_result_list[c$uid]["resp"];
            vcr[|vcr|] = tt;
            iat_result_list[c$uid]["resp"] = vcr;
	    }
	    conn_list_resp[c$uid] = network_time();
        # pktsize
        local pkts2: double = len;
        local vpkts2: vector of double = pktsz_result_list[c$uid]["resp"];
        vpkts2[|vpkts2|] = pkts2;
        pktsz_result_list[c$uid]["resp"] = vpkts2;
    }
}

event connection_state_remove(c: connection)
    {
        if (c$uid in iat_result_list){
            local mx_vl_orig: double = IAT::max_value(iat_result_list[c$uid]["orig"]);
            local mn_vl_orig: double = IAT::min_value(iat_result_list[c$uid]["orig"]);
            local sm_vl_orig: double = IAT::sum_value(iat_result_list[c$uid]["orig"]);
            local ag_vl_orig: double = IAT::avg_value(iat_result_list[c$uid]["orig"]);
            local ln_vl_orig: count = IAT::len_value(iat_result_list[c$uid]["orig"]);
            local mx_vl_resp: double = IAT::max_value(iat_result_list[c$uid]["resp"]);
            local mn_vl_resp: double = IAT::min_value(iat_result_list[c$uid]["resp"]);
            local sm_vl_resp: double = IAT::sum_value(iat_result_list[c$uid]["resp"]);
            local ag_vl_resp: double = IAT::avg_value(iat_result_list[c$uid]["resp"]);
            local ln_vl_resp: count = IAT::len_value(iat_result_list[c$uid]["resp"]);
            # compute overall statistics
            iat_result_list[c$uid]["tot"] = merge_vectors(iat_result_list[c$uid]["orig"], iat_result_list[c$uid]["resp"]);
            local mx_vl_tot: double = IAT::max_value(iat_result_list[c$uid]["tot"]);
            local mn_vl_tot: double = IAT::min_value(iat_result_list[c$uid]["tot"]);
            local sm_vl_tot: double = IAT::sum_value(iat_result_list[c$uid]["tot"]);
            local ag_vl_tot: double = IAT::avg_value(iat_result_list[c$uid]["tot"]);
            local rec = IAT::IATInfo($uid = c$uid, $id = c$id, 
                                        $orig_max_IAT = mx_vl_orig, $orig_min_IAT = mn_vl_orig, $orig_sum_IAT = sm_vl_orig, $orig_ave_IAT = ag_vl_orig, 
                                        $resp_max_IAT = mx_vl_resp, $resp_min_IAT = mn_vl_resp, $resp_sum_IAT = sm_vl_resp, $resp_ave_IAT = ag_vl_resp,
                                        $tot_max_IAT = mx_vl_tot, $tot_min_IAT = mn_vl_tot, $tot_sum_IAT = sm_vl_tot, $tot_ave_IAT = ag_vl_tot);
            delete iat_result_list[c$uid];
            c$conn$orig_max_IAT = mx_vl_orig;
            c$conn$orig_min_IAT = mn_vl_orig;
            c$conn$orig_sum_IAT = sm_vl_orig;
            c$conn$orig_ave_IAT = ag_vl_orig;
            c$conn$resp_max_IAT = mx_vl_resp;
            c$conn$resp_min_IAT = mn_vl_resp;
            c$conn$resp_sum_IAT = sm_vl_resp;
            c$conn$resp_ave_IAT = ag_vl_resp;
            c$conn$tot_max_IAT = mx_vl_tot;
            c$conn$tot_min_IAT = mn_vl_tot;
            c$conn$tot_sum_IAT = sm_vl_tot;
            c$conn$tot_ave_IAT = ag_vl_tot;
            Log::write(IAT::LOG, rec);
        }
        if (c$uid in pktsz_result_list){
            local mx_vl_orig1: double = IAT::max_value(pktsz_result_list[c$uid]["orig"]);
            local mn_vl_orig1: double = IAT::min_value(pktsz_result_list[c$uid]["orig"]);
            local sm_vl_orig1: double = IAT::sum_value(pktsz_result_list[c$uid]["orig"]);
            local ag_vl_orig1: double = IAT::avg_value(pktsz_result_list[c$uid]["orig"]);
            local mx_vl_resp1: double = IAT::max_value(pktsz_result_list[c$uid]["resp"]);
            local mn_vl_resp1: double = IAT::min_value(pktsz_result_list[c$uid]["resp"]);
            local sm_vl_resp1: double = IAT::sum_value(pktsz_result_list[c$uid]["resp"]);
            local ag_vl_resp1: double = IAT::avg_value(pktsz_result_list[c$uid]["resp"]);
            c$conn$orig_max_pktsz = mx_vl_orig1;
            c$conn$orig_min_pktsz = mn_vl_orig1;
            c$conn$orig_sum_pktsz = sm_vl_orig1;
            c$conn$orig_ave_pktsz = ag_vl_orig1;
            c$conn$resp_max_pktsz = mx_vl_resp1;
            c$conn$resp_min_pktsz = mn_vl_resp1;
            c$conn$resp_sum_pktsz = sm_vl_resp1;
            c$conn$resp_ave_pktsz = ag_vl_resp1;
            delete pktsz_result_list[c$uid];
        }
        if (c$uid in winsz_result_list){
            local res: count = winsz_result_list[c$uid];
            c$conn$orig_tcpinitsize = res;
        }
    }
