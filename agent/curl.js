
const curlopts = {"1":{"type":"OBJECTPOINT","name":"writedata"},"2":{"type":"STRINGPOINT","name":"url"},"3":{"type":"LONG","name":"port"},"4":{"type":"STRINGPOINT","name":"proxy"},"5":{"type":"STRINGPOINT","name":"userpwd"},"6":{"type":"STRINGPOINT","name":"proxyuserpwd"},"7":{"type":"STRINGPOINT","name":"range"},"9":{"type":"OBJECTPOINT","name":"readdata"},"10":{"type":"OBJECTPOINT","name":"errorbuffer"},"11":{"type":"FUNCTIONPOINT","name":"writefunction"},"12":{"type":"FUNCTIONPOINT","name":"readfunction"},"13":{"type":"LONG","name":"timeout"},"14":{"type":"LONG","name":"infilesize"},"15":{"type":"OBJECTPOINT","name":"postfields"},"16":{"type":"STRINGPOINT","name":"referer"},"17":{"type":"STRINGPOINT","name":"ftpport"},"18":{"type":"STRINGPOINT","name":"useragent"},"19":{"type":"LONG","name":"low_speed_limit"},"20":{"type":"LONG","name":"low_speed_time"},"21":{"type":"LONG","name":"resume_from"},"22":{"type":"STRINGPOINT","name":"cookie"},"23":{"type":"SLISTPOINT","name":"httpheader"},"24":{"type":"OBJECTPOINT","name":"httppost"},"25":{"type":"STRINGPOINT","name":"sslcert"},"26":{"type":"STRINGPOINT","name":"keypasswd"},"27":{"type":"LONG","name":"crlf"},"28":{"type":"SLISTPOINT","name":"quote"},"29":{"type":"OBJECTPOINT","name":"headerdata"},"31":{"type":"STRINGPOINT","name":"cookiefile"},"32":{"type":"LONG","name":"sslversion"},"33":{"type":"LONG","name":"timecondition"},"34":{"type":"LONG","name":"timevalue"},"36":{"type":"STRINGPOINT","name":"customrequest"},"37":{"type":"OBJECTPOINT","name":"stderr"},"39":{"type":"SLISTPOINT","name":"postquote"},"40":{"type":"OBJECTPOINT","name":"obsolete40"},"41":{"type":"LONG","name":"verbose"},"42":{"type":"LONG","name":"header"},"43":{"type":"LONG","name":"noprogress"},"44":{"type":"LONG","name":"nobody"},"45":{"type":"LONG","name":"failonerror"},"46":{"type":"LONG","name":"upload"},"47":{"type":"LONG","name":"post"},"48":{"type":"LONG","name":"dirlistonly"},"50":{"type":"LONG","name":"append"},"51":{"type":"LONG","name":"netrc"},"52":{"type":"LONG","name":"followlocation"},"53":{"type":"LONG","name":"transfertext"},"54":{"type":"LONG","name":"put"},"56":{"type":"FUNCTIONPOINT","name":"progressfunction"},"57":{"type":"OBJECTPOINT","name":"progressdata"},"58":{"type":"LONG","name":"autoreferer"},"59":{"type":"LONG","name":"proxyport"},"60":{"type":"LONG","name":"postfieldsize"},"61":{"type":"LONG","name":"httpproxytunnel"},"62":{"type":"STRINGPOINT","name":"interface"},"63":{"type":"STRINGPOINT","name":"krblevel"},"64":{"type":"LONG","name":"ssl_verifypeer"},"65":{"type":"STRINGPOINT","name":"cainfo"},"68":{"type":"LONG","name":"maxredirs"},"69":{"type":"LONG","name":"filetime"},"70":{"type":"SLISTPOINT","name":"telnetoptions"},"71":{"type":"LONG","name":"maxconnects"},"72":{"type":"LONG","name":"obsolete72"},"74":{"type":"LONG","name":"fresh_connect"},"75":{"type":"LONG","name":"forbid_reuse"},"76":{"type":"STRINGPOINT","name":"random_file"},"77":{"type":"STRINGPOINT","name":"egdsocket"},"78":{"type":"LONG","name":"connecttimeout"},"79":{"type":"FUNCTIONPOINT","name":"headerfunction"},"80":{"type":"LONG","name":"httpget"},"81":{"type":"LONG","name":"ssl_verifyhost"},"82":{"type":"STRINGPOINT","name":"cookiejar"},"83":{"type":"STRINGPOINT","name":"ssl_cipher_list"},"84":{"type":"LONG","name":"http_version"},"85":{"type":"LONG","name":"ftp_use_epsv"},"86":{"type":"STRINGPOINT","name":"sslcerttype"},"87":{"type":"STRINGPOINT","name":"sslkey"},"88":{"type":"STRINGPOINT","name":"sslkeytype"},"89":{"type":"STRINGPOINT","name":"sslengine"},"90":{"type":"LONG","name":"sslengine_default"},"91":{"type":"LONG","name":"dns_use_global_cache"},"92":{"type":"LONG","name":"dns_cache_timeout"},"93":{"type":"SLISTPOINT","name":"prequote"},"94":{"type":"FUNCTIONPOINT","name":"debugfunction"},"95":{"type":"OBJECTPOINT","name":"debugdata"},"96":{"type":"LONG","name":"cookiesession"},"97":{"type":"STRINGPOINT","name":"capath"},"98":{"type":"LONG","name":"buffersize"},"99":{"type":"LONG","name":"nosignal"},"100":{"type":"OBJECTPOINT","name":"share"},"101":{"type":"LONG","name":"proxytype"},"102":{"type":"STRINGPOINT","name":"accept_encoding"},"103":{"type":"OBJECTPOINT","name":"private"},"104":{"type":"SLISTPOINT","name":"http200aliases"},"105":{"type":"LONG","name":"unrestricted_auth"},"106":{"type":"LONG","name":"ftp_use_eprt"},"107":{"type":"LONG","name":"httpauth"},"108":{"type":"FUNCTIONPOINT","name":"ssl_ctx_function"},"109":{"type":"OBJECTPOINT","name":"ssl_ctx_data"},"110":{"type":"LONG","name":"ftp_create_missing_dirs"},"111":{"type":"LONG","name":"proxyauth"},"112":{"type":"LONG","name":"ftp_response_timeout"},"113":{"type":"LONG","name":"ipresolve"},"114":{"type":"LONG","name":"maxfilesize"},"115":{"type":"OFF_T","name":"infilesize_large"},"116":{"type":"OFF_T","name":"resume_from_large"},"117":{"type":"OFF_T","name":"maxfilesize_large"},"118":{"type":"STRINGPOINT","name":"netrc_file"},"119":{"type":"LONG","name":"use_ssl"},"120":{"type":"OFF_T","name":"postfieldsize_large"},"121":{"type":"LONG","name":"tcp_nodelay"},"129":{"type":"LONG","name":"ftpsslauth"},"130":{"type":"FUNCTIONPOINT","name":"ioctlfunction"},"131":{"type":"OBJECTPOINT","name":"ioctldata"},"134":{"type":"STRINGPOINT","name":"ftp_account"},"135":{"type":"STRINGPOINT","name":"cookielist"},"136":{"type":"LONG","name":"ignore_content_length"},"137":{"type":"LONG","name":"ftp_skip_pasv_ip"},"138":{"type":"LONG","name":"ftp_filemethod"},"139":{"type":"LONG","name":"localport"},"140":{"type":"LONG","name":"localportrange"},"141":{"type":"LONG","name":"connect_only"},"142":{"type":"FUNCTIONPOINT","name":"conv_from_network_function"},"143":{"type":"FUNCTIONPOINT","name":"conv_to_network_function"},"144":{"type":"FUNCTIONPOINT","name":"conv_from_utf8_function"},"145":{"type":"OFF_T","name":"max_send_speed_large"},"146":{"type":"OFF_T","name":"max_recv_speed_large"},"147":{"type":"STRINGPOINT","name":"ftp_alternative_to_user"},"148":{"type":"FUNCTIONPOINT","name":"sockoptfunction"},"149":{"type":"OBJECTPOINT","name":"sockoptdata"},"150":{"type":"LONG","name":"ssl_sessionid_cache"},"151":{"type":"LONG","name":"ssh_auth_types"},"152":{"type":"STRINGPOINT","name":"ssh_public_keyfile"},"153":{"type":"STRINGPOINT","name":"ssh_private_keyfile"},"154":{"type":"LONG","name":"ftp_ssl_ccc"},"155":{"type":"LONG","name":"timeout_ms"},"156":{"type":"LONG","name":"connecttimeout_ms"},"157":{"type":"LONG","name":"http_transfer_decoding"},"158":{"type":"LONG","name":"http_content_decoding"},"159":{"type":"LONG","name":"new_file_perms"},"160":{"type":"LONG","name":"new_directory_perms"},"161":{"type":"LONG","name":"postredir"},"162":{"type":"STRINGPOINT","name":"ssh_host_public_key_md5"},"163":{"type":"FUNCTIONPOINT","name":"opensocketfunction"},"164":{"type":"OBJECTPOINT","name":"opensocketdata"},"165":{"type":"OBJECTPOINT","name":"copypostfields"},"166":{"type":"LONG","name":"proxy_transfer_mode"},"167":{"type":"FUNCTIONPOINT","name":"seekfunction"},"168":{"type":"OBJECTPOINT","name":"seekdata"},"169":{"type":"STRINGPOINT","name":"crlfile"},"170":{"type":"STRINGPOINT","name":"issuercert"},"171":{"type":"LONG","name":"address_scope"},"172":{"type":"LONG","name":"certinfo"},"173":{"type":"STRINGPOINT","name":"username"},"174":{"type":"STRINGPOINT","name":"password"},"175":{"type":"STRINGPOINT","name":"proxyusername"},"176":{"type":"STRINGPOINT","name":"proxypassword"},"177":{"type":"STRINGPOINT","name":"noproxy"},"178":{"type":"LONG","name":"tftp_blksize"},"179":{"type":"STRINGPOINT","name":"socks5_gssapi_service"},"180":{"type":"LONG","name":"socks5_gssapi_nec"},"181":{"type":"LONG","name":"protocols"},"182":{"type":"LONG","name":"redir_protocols"},"183":{"type":"STRINGPOINT","name":"ssh_knownhosts"},"184":{"type":"FUNCTIONPOINT","name":"ssh_keyfunction"},"185":{"type":"OBJECTPOINT","name":"ssh_keydata"},"186":{"type":"STRINGPOINT","name":"mail_from"},"187":{"type":"SLISTPOINT","name":"mail_rcpt"},"188":{"type":"LONG","name":"ftp_use_pret"},"189":{"type":"LONG","name":"rtsp_request"},"190":{"type":"STRINGPOINT","name":"rtsp_session_id"},"191":{"type":"STRINGPOINT","name":"rtsp_stream_uri"},"192":{"type":"STRINGPOINT","name":"rtsp_transport"},"193":{"type":"LONG","name":"rtsp_client_cseq"},"194":{"type":"LONG","name":"rtsp_server_cseq"},"195":{"type":"OBJECTPOINT","name":"interleavedata"},"196":{"type":"FUNCTIONPOINT","name":"interleavefunction"},"197":{"type":"LONG","name":"wildcardmatch"},"198":{"type":"FUNCTIONPOINT","name":"chunk_bgn_function"},"199":{"type":"FUNCTIONPOINT","name":"chunk_end_function"},"200":{"type":"FUNCTIONPOINT","name":"fnmatch_function"},"201":{"type":"OBJECTPOINT","name":"chunk_data"},"202":{"type":"OBJECTPOINT","name":"fnmatch_data"},"203":{"type":"SLISTPOINT","name":"resolve"},"204":{"type":"STRINGPOINT","name":"tlsauth_username"},"205":{"type":"STRINGPOINT","name":"tlsauth_password"},"206":{"type":"STRINGPOINT","name":"tlsauth_type"},"207":{"type":"LONG","name":"transfer_encoding"},"208":{"type":"FUNCTIONPOINT","name":"closesocketfunction"},"209":{"type":"OBJECTPOINT","name":"closesocketdata"},"210":{"type":"LONG","name":"gssapi_delegation"},"211":{"type":"STRINGPOINT","name":"dns_servers"},"212":{"type":"LONG","name":"accepttimeout_ms"},"213":{"type":"LONG","name":"tcp_keepalive"},"214":{"type":"LONG","name":"tcp_keepidle"},"215":{"type":"LONG","name":"tcp_keepintvl"},"216":{"type":"LONG","name":"ssl_options"},"217":{"type":"STRINGPOINT","name":"mail_auth"},"218":{"type":"LONG","name":"sasl_ir"},"219":{"type":"FUNCTIONPOINT","name":"xferinfofunction"},"220":{"type":"STRINGPOINT","name":"xoauth2_bearer"},"221":{"type":"STRINGPOINT","name":"dns_interface"},"222":{"type":"STRINGPOINT","name":"dns_local_ip4"},"223":{"type":"STRINGPOINT","name":"dns_local_ip6"},"224":{"type":"STRINGPOINT","name":"login_options"},"225":{"type":"LONG","name":"ssl_enable_npn"},"226":{"type":"LONG","name":"ssl_enable_alpn"},"227":{"type":"LONG","name":"expect_100_timeout_ms"},"228":{"type":"SLISTPOINT","name":"proxyheader"},"229":{"type":"LONG","name":"headeropt"},"230":{"type":"STRINGPOINT","name":"pinnedpublickey"},"231":{"type":"STRINGPOINT","name":"unix_socket_path"},"232":{"type":"LONG","name":"ssl_verifystatus"},"233":{"type":"LONG","name":"ssl_falsestart"},"234":{"type":"LONG","name":"path_as_is"},"235":{"type":"STRINGPOINT","name":"proxy_service_name"},"236":{"type":"STRINGPOINT","name":"service_name"},"237":{"type":"LONG","name":"pipewait"},"238":{"type":"STRINGPOINT","name":"default_protocol"},"239":{"type":"LONG","name":"stream_weight"},"240":{"type":"OBJECTPOINT","name":"stream_depends"},"241":{"type":"OBJECTPOINT","name":"stream_depends_e"},"242":{"type":"LONG","name":"tftp_no_options"},"243":{"type":"SLISTPOINT","name":"connect_to"},"244":{"type":"LONG","name":"tcp_fastopen"},"245":{"type":"LONG","name":"keep_sending_on_error"},"246":{"type":"STRINGPOINT","name":"proxy_cainfo"},"247":{"type":"STRINGPOINT","name":"proxy_capath"},"248":{"type":"LONG","name":"proxy_ssl_verifypeer"},"249":{"type":"LONG","name":"proxy_ssl_verifyhost"},"250":{"type":"LONG","name":"proxy_sslversion"},"251":{"type":"STRINGPOINT","name":"proxy_tlsauth_username"},"252":{"type":"STRINGPOINT","name":"proxy_tlsauth_password"},"253":{"type":"STRINGPOINT","name":"proxy_tlsauth_type"},"254":{"type":"STRINGPOINT","name":"proxy_sslcert"},"255":{"type":"STRINGPOINT","name":"proxy_sslcerttype"},"256":{"type":"STRINGPOINT","name":"proxy_sslkey"},"257":{"type":"STRINGPOINT","name":"proxy_sslkeytype"},"258":{"type":"STRINGPOINT","name":"proxy_keypasswd"},"259":{"type":"STRINGPOINT","name":"proxy_ssl_cipher_list"},"260":{"type":"STRINGPOINT","name":"proxy_crlfile"},"261":{"type":"LONG","name":"proxy_ssl_options"},"262":{"type":"STRINGPOINT","name":"pre_proxy"},"263":{"type":"STRINGPOINT","name":"proxy_pinnedpublickey"},"264":{"type":"STRINGPOINT","name":"abstract_unix_socket"},"265":{"type":"LONG","name":"suppress_connect_headers"},"266":{"type":"STRINGPOINT","name":"request_target"},"267":{"type":"LONG","name":"socks5_auth"},"268":{"type":"LONG","name":"ssh_compression"},"269":{"type":"OBJECTPOINT","name":"mimepost"},"270":{"type":"OFF_T","name":"timevalue_large"},"271":{"type":"LONG","name":"happy_eyeballs_timeout_ms"},"272":{"type":"FUNCTIONPOINT","name":"resolver_start_function"},"273":{"type":"OBJECTPOINT","name":"resolver_start_data"},"274":{"type":"LONG","name":"haproxyprotocol"},"275":{"type":"LONG","name":"dns_shuffle_addresses"},"276":{"type":"STRINGPOINT","name":"tls13_ciphers"},"277":{"type":"STRINGPOINT","name":"proxy_tls13_ciphers"},"278":{"type":"LONG","name":"disallow_username_in_url"},"279":{"type":"STRINGPOINT","name":"doh_url"},"280":{"type":"LONG","name":"upload_buffersize"},"281":{"type":"LONG","name":"upkeep_interval_ms"},"282":{"type":"OBJECTPOINT","name":"curlu"},"283":{"type":"FUNCTIONPOINT","name":"trailerfunction"},"284":{"type":"OBJECTPOINT","name":"trailerdata"},"285":{"type":"LONG","name":"http09_allowed"},"286":{"type":"LONG","name":"altsvc_ctrl"},"287":{"type":"STRINGPOINT","name":"altsvc"},"288":{"type":"LONG","name":"maxage_conn"},"289":{"type":"STRINGPOINT","name":"sasl_authzid"}};

const na = require("./native.js");
na.modules.c.fwrite = ['uint', ['pointer', 'uint', 'uint', 'pointer']];
const curl_infos = {};

function slist_to_array(slist) {
    let arr = [];
    while(!slist.isNull()) {
        arr.push(slist.readPointer().readCString());
        slist = slist.add(Process.pointerSize).readPointer();
    }
    return arr;
}

let memory_refs = [];
function clear_refs() { memory_refs = []; }
function slist_append(slist, data) {
    let last = ptr(0);
    let tmem;
    let current = slist;
    while(!current.isNull()) {
        last = current;
        current = current.add(Process.pointerSize).readPointer();
    }
    let newSlist = Memory.alloc(2*Process.pointerSize);
    memory_refs.push(newSlist);
    newSlist.add(Process.pointerSize).writePointer(ptr(0));
    if(slist.isNull()) slist = newSlist;
    else last.add(Process.pointerSize).writePointer(newSlist);
    
    if(typeof(data) === 'string') {
        tmem = Memory.allocUtf8String(data);
        memory_refs.push(tmem);
        newSlist.writePointer(tmem);
    }
    else if(data instanceof NativePointer) {
        newSlist.writePointer(data);
    }
    
    return slist;
}

function find_optid(name) {
    for(let optid in curlopts) {
        let optinfo = curlopts[optid];
        if(optinfo.name == name) {
            optid = parseInt(optid);
            switch(optinfo.type) {
                case "LONG":
                    return optid;
                case "OBJECTPOINT":
                case "STRINGPOINT":
                case "SLISTPOINT":
                    return 10000 + optid;
                case "FUNCTIONPOINT":
                    return 20000 + optid;
                case "OFF_T":
                    return 30000 + optid;
            }
        }
    }
}

let _curl_easy_setopt = null;
function curl_easy_setopt(instance, name, value) {
    let id = find_optid(name);
    let optid = id % 1000;
    let optinfo = curlopts[optid];
    let valuehandle = ptr(0);
    if(value instanceof NativePointer) {
        valuehandle = value;
    }
    else {
        switch(optinfo.type) {
            case "LONG":
            case "OFF_T":
                valuehandle = ptr(value);
                break;
            case "OBJECTPOINT":
            case "STRINGPOINT":
                valuehandle = Memory.allocUtf8String(value.toString());
                break;
            case "SLISTPOINT":
                let slist = ptr(0);
                for(let i in value) {
                    slist = slist_append(slist, value[i]);
                }
                valuehandle = slist;
                break;
            case "FUNCTIONPOINT":
                if(value instanceof Function) {
                    let argtypes = new Array(value.length);
                    argtypes.fill("pointer");
                    valuehandle = new NativeCallback(value, 'pointer', argtypes);
                }
                else valuehandle = ptr(0); // ...
                break;
        }
    }
    let ret = _curl_easy_setopt(instance, id, valuehandle);
    if(ret != 0) {
        console.log("error when call curl_easy_setopt:", ret, name);
    }
    // clear_refs();
}

function hook_setopt(setopt_faddr, fn, options) {
    _curl_easy_setopt = new NativeFunction(setopt_faddr, 'int', ['pointer', 'int', 'pointer']);
    Interceptor.attach(setopt_faddr, {
        onEnter: function(args) {
            let instance = ptr(args[0]);
            let optid = args[1].toInt32() % 1000;
            let handle = args[2];
            let optinfo = curlopts[optid];
            let optvalue = null;
            
            if(curl_infos[instance] === undefined || curl_infos[instance][optinfo.name] !== undefined) {
                curl_infos[instance] = {};
                if(options && options.override) {
                    for(let name in options.override) {
                        curl_easy_setopt(instance, name, options.override[name]);
                    }
                }
            }
            
            threadData.last_curl_info = curl_infos[instance];
            switch(optinfo.type) {
                case "LONG":
                    optvalue = handle.toInt32();
                    break;
                case "OBJECTPOINT":
                    optvalue = handle;
                    break;
                case "STRINGPOINT":
                    if(handle.isNull()) optvalue = 'nullptr';
                    else optvalue = handle.readCString();
                    break;
                case "SLISTPOINT":
                    optvalue = slist_to_array(handle);
                    break;
                case "FUNCTIONPOINT":
                    optvalue = handle;
                    break;
                case "OFF_T":
                    optvalue = handle.toUInt32();
                    break;
            }
            let loginfo = `curl_easy_setopt(${args[0]}, ${args[1].toUInt32()}:${optinfo.name}, ${optvalue});`;
            curl_infos[instance][optinfo.name] = optvalue;
            if(options && optinfo.name in options.override) {
                // console.log("overrided", loginfo);
                // override any to set ssl_verifypeer 0
                args[1] = ptr(find_optid("ssl_verifypeer"));
                args[2] = ptr(0);
                return;
            }
            if(fn instanceof Function) {
                let ret = fn.apply(this, [instance, optinfo, optvalue, args]);
                if(ret !== undefined && ret !== null) {
                    args[2] = ret;
                    handle = ret;
                }
            }
            else {
                console.log(loginfo);
                if(optinfo.name == 'postfields') {
                    console.log(handle.readCString());
                }
            }
            
            switch(optinfo.name) {
                case 'postfields':
                case 'postfieldsize':
                    if(curl_infos[instance].postfields && curl_infos[instance].postfieldsize) {
                        curl_infos[instance].postdata = curl_infos[instance].postfields.readByteArray(curl_infos[instance].postfieldsize);
                    }
                    break;
                default:
                    break;
            }
        }
    });
    Interceptor.flush();
}

module.exports = {
    hook_setopt,
    curl_easy_setopt,
    slist_to_array,
    slist_append,
    curl_infos
};