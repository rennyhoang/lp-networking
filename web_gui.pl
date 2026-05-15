%  web_gui.pl  —  HTTP dashboard for network_monitor
%
%  $ swipl -l network_monitor.pl -l web_gui.pl
%  ?- start_server.        %% → http://localhost:8080
%  ?- start_server(9090).  %% custom port

:- module(web_gui, [start_server/0, start_server/1]).

:- use_module(library(http/thread_httpd)).
:- use_module(library(http/http_dispatch)).
:- use_module(library(http/http_files)).
:- use_module(library(http/http_json)).
:- use_module(library(aggregate)).
:- use_module(library(apply)).
:- use_module(library(lists)).
:- use_module(library(pairs)).
:- use_module(network_monitor).

% server shouldn't depend on working directory
:- dynamic static_dir/1.
:- prolog_load_context(directory, D),
   atomic_list_concat([D, '/static'], S),
   assertz(static_dir(S)).


% Routes
% Static files
:- http_handler('/', serve_static, [prefix]).

% Read-only API
:- http_handler('/api/summary', api_summary, [method(get)]).
:- http_handler('/api/threats', api_threats, [method(get)]).
:- http_handler('/api/data',    api_data,    [method(get)]).

% Load endpoints
:- http_handler('/api/load/connections', api_load_connections, [method(post)]).
:- http_handler('/api/load/auth',        api_load_auth,        [method(post)]).
:- http_handler('/api/load/pcap',        api_load_pcap,        [method(post)]).

% Server startup
start_server :- start_server(8080).
start_server(Port) :-
    http_server(http_dispatch, [port(Port), workers(4)]),
    format("~n[+] Dashboard → http://localhost:~w/~n", [Port]),
    format("    Load data from the REPL or the browser's Load panel.~n~n").

%%  Static file handler
serve_static(Request) :-
    static_dir(Dir),
    http_reply_from_files(Dir, [indexes(['index.html'])], Request).

% GET /api/summary
api_summary(_Request) :-
    aggregate_all(count, network_monitor:connection(_,_,_,_,_,_), Conn),
    aggregate_all(count, network_monitor:login_attempt(_,_,_,_),  Auth),
    aggregate_all(count, network_monitor:blacklisted_ip(_),        BL),
    unique_threats(Threats),
    length(Threats, TN),
    reply_json_dict(_{
        connections:     Conn,
        auth_events:     Auth,
        blacklisted_ips: BL,
        threat_count:    TN
    }).

% GET /api/threats
api_threats(_Request) :-
    unique_threats(Threats),
    maplist(threat_to_dict, Threats, Dicts),
    reply_json_dict(_{threats: Dicts}).

threat_to_dict(threat(Type, Key, Evidence),
               _{type: TypeS, severity: SevS, target: KeyS, evidence: EvidS}) :-
    atom_string(Type,     TypeS),
    term_string(Key,      KeyS),
    term_string(Evidence, EvidS),
    sev_string(Type, SevS).

sev_string(port_scan,        "HIGH").
sev_string(brute_force,      "HIGH").
sev_string(data_exfiltration,"CRITICAL").
sev_string(lateral_movement, "HIGH").
sev_string(blacklist_hit,    "CRITICAL").

% GET /api/data
api_data(_Request) :-
    connections_by_hour(TimeLabels, TimeCounts),
    proto_distribution(ProtoLabels, ProtoCounts),
    top_sources(SrcLabels, SrcCounts),
    auth_by_hour(AuthLabels, FailedCounts, SuccessCounts),
    reply_json_dict(_{
        connections_over_time: _{labels: TimeLabels, data: TimeCounts},
        protocol_distribution: _{labels: ProtoLabels, data: ProtoCounts},
        top_sources:           _{labels: SrcLabels,  data: SrcCounts},
        auth_timeline:         _{labels: AuthLabels,
                                  failed:  FailedCounts,
                                  success: SuccessCounts}
    }).

% Connection count bucketed by hour
connections_by_hour(Labels, Counts) :-
    findall(H,
        ( network_monitor:connection(Ts,_,_,_,_,_),
          H is round(Ts) // 3600 ),
        Hours),
    ( Hours = [] ->
        Labels = [], Counts = []
    ;
        min_list(Hours, MinH), max_list(Hours, MaxH),
        numlist(MinH, MaxH, HRange),
        maplist([H, L]>>(S is H*3600, format_time(atom(L), '%m/%d %H:00', S)),
                HRange, Labels),
        maplist([H, C]>>(
            aggregate_all(count,
                ( network_monitor:connection(Ts2,_,_,_,_,_),
                  round(Ts2) // 3600 =:= H ),
                C)
        ), HRange, Counts)
    ).

% Distinct protocol counts
proto_distribution(Labels, Counts) :-
    aggregate_all(set(P), network_monitor:connection(_,_,_,_,_,P), Protos),
    ( Protos = [] ->
        Labels = [], Counts = []
    ;
        maplist([P, C]>>(
            aggregate_all(count, network_monitor:connection(_,_,_,_,_,P), C)
        ), Protos, Counts),
        maplist(atom_string, Protos, Labels)
    ).

% Top 10 source IPs by connection count
top_sources(Labels, Counts) :-
    aggregate_all(set(S), network_monitor:connection(_,S,_,_,_,_), Srcs),
    ( Srcs = [] ->
        Labels = [], Counts = []
    ;
        maplist([S, C-S]>>(
            aggregate_all(count, network_monitor:connection(_,S,_,_,_,_), C)
        ), Srcs, Pairs),
        msort(Pairs, Asc), reverse(Asc, Desc),
        length(Desc, Total), N is min(Total, 10),
        length(Top, N), append(Top, _, Desc),
        pairs_keys_values(Top, Counts, SrcAtoms),
        maplist(atom_string, SrcAtoms, Labels)
    ).

% Auth event counts bucketed by hour, split by result
auth_by_hour(Labels, Failed, Success) :-
    findall(H,
        ( network_monitor:login_attempt(Ts,_,_,_),
          H is round(Ts) // 3600 ),
        Hours),
    ( Hours = [] ->
        Labels = [], Failed = [], Success = []
    ;
        min_list(Hours, MinH), max_list(Hours, MaxH),
        numlist(MinH, MaxH, HRange),
        maplist([H, L]>>(S is H*3600, format_time(atom(L), '%m/%d %H:00', S)),
                HRange, Labels),
        maplist([H, C]>>(
            aggregate_all(count,
                ( network_monitor:login_attempt(Ts2,_,_,failed),
                  round(Ts2) // 3600 =:= H ), C)
        ), HRange, Failed),
        maplist([H, C]>>(
            aggregate_all(count,
                ( network_monitor:login_attempt(Ts2,_,_,success),
                  round(Ts2) // 3600 =:= H ), C)
        ), HRange, Success)
    ).

% POST /api/load/*
api_load_connections(Request) :- handle_load(Request, load_connection_log).
api_load_auth(Request)        :- handle_load(Request, load_auth_log).
api_load_pcap(Request)        :- handle_load(Request, load_pcap).

handle_load(Request, Loader) :-
    catch(
        run_load(Request, Loader),
        Err,
        respond_load_error(Err)
    ).

run_load(Request, Loader) :-
    http_read_json_dict(Request, Body),
    ( get_dict(file, Body, FileStr) ->
        atom_string(File, FileStr),
        %% Redirect loader's console output to stderr so it doesn't corrupt the
        %% HTTP response stream (current_output is the CGI stream in a handler).
        with_output_to(user_error, call(Loader, File))
    ;
        throw(missing_file_key)
    ),
    aggregate_all(count, network_monitor:connection(_,_,_,_,_,_), N),
    reply_json_dict(_{status: "ok", loaded: N}).

respond_load_error(missing_file_key) :- !,
    reply_json_dict(_{status: "error",
                      message: "JSON body must contain a 'file' key"}).
respond_load_error(error(existence_error(source_sink, F), _)) :- !,
    format(atom(Msg), "File not found: ~w", [F]),
    reply_json_dict(_{status: "error", message: Msg}).
respond_load_error(Err) :-
    term_string(Err, S),
    reply_json_dict(_{status: "error", message: S}).
