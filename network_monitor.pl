%%  network_monitor.pl  —  Network Intrusion Detection in SWI-Prolog
%%
%%  Interactive:
%%    $ swipl network_monitor.pl
%%    ?- load_connection_log('sample_connections.log').
%%    ?- load_auth_log('sample_auth.log').
%%    ?- analyze.
%%
%%  One-shot:
%%    $ swipl -g "load_connection_log('sample_connections.log'), \
%%               load_auth_log('sample_auth.log'), analyze, halt." \
%%            network_monitor.pl
%%
%%  Command-line (after --):
%%    $ swipl -g main network_monitor.pl -- sample_connections.log sample_auth.log

:- module(network_monitor, [
    analyze/0,
    load_connection_log/1,
    load_auth_log/1,
    add_to_blacklist/1,
    clear_data/0,
    threat/3,
    unique_threats/1,
    load_pcap/1
]).

:- use_module(library(aggregate)).
:- use_module(library(apply)).
:- use_module(library(lists)).
:- use_module(library(process)).

%% ===========================================================
%%  Thresholds — tune these to control sensitivity
%% ===========================================================

threshold(port_scan_count,    10).   % distinct ports to same dst in window
threshold(port_scan_window,   60).   % seconds
threshold(brute_force_count,  5).    % failed logins from same src in window
threshold(brute_force_window, 300).  % seconds (5 minutes)
threshold(exfil_bytes,    10000000). % 10 MB — single-connection threshold
threshold(lateral_hosts,      5).    % unique internal dsts from one src

%% ===========================================================
%%  Dynamic fact store
%% ===========================================================

:- dynamic connection/6.
%% connection(+UnixTs, +SrcIP, +DstIP, +DstPort, +BytesOut, +Protocol)

:- dynamic login_attempt/4.
%% login_attempt(+UnixTs, +SrcIP, +Username, +Result)
%% Result ∈ { failed, success, invalid_user }

:- dynamic blacklisted_ip/1.

%% Seed blacklist (known Tor exits / attack sources — for demonstration)
:- maplist([IP]>>(assertz(blacklisted_ip(IP))), [
    '185.220.101.1',
    '185.220.101.2',
    '45.33.32.156',
    '198.98.51.189',
    '23.129.64.131'
]).

add_to_blacklist(IP) :-
    atom(IP),
    ( blacklisted_ip(IP) -> true ; assertz(blacklisted_ip(IP)) ).

clear_data :-
    retractall(connection(_, _, _, _, _, _)),
    retractall(login_attempt(_, _, _, _)).

%% ===========================================================
%%  PCAP loader  (requires tshark from wireshark-cli)
%%
%%  Usage:  ?- load_pcap('capture.pcap').
%%
%%  Install tshark:
%%    sudo pacman -S wireshark-cli       # Arch / CachyOS
%%    sudo apt  install tshark           # Debian / Ubuntu
%%    brew install wireshark             # macOS
%% ===========================================================

load_pcap(File) :-
    catch(
        load_pcap_(File),
        error(existence_error(_, _), _),
        ( format(user_error,
              "[!] tshark not found — install wireshark-cli and retry.~n", []),
          fail )
    ).

load_pcap_(File) :-
    retractall(connection(_, _, _, _, _, _)),
    process_create(path(tshark),
        [ '-r',  File,
          '-T',  fields,
          '-e',  'frame.time_epoch',
          '-e',  'ip.src',
          '-e',  'ip.dst',
          '-e',  'tcp.dstport',
          '-e',  'udp.dstport',
          '-e',  'frame.len',
          '-E',  'separator=,',
          '-E',  'occurrence=f',
          '-E',  'header=n'
        ],
        [ stdout(pipe(Out)),
          stderr(null),
          process(PID)
        ]),
    read_pcap_stream(Out, 0, N),
    close(Out),
    process_wait(PID, _),
    format("[+] Loaded ~w connection(s) from PCAP '~w'~n", [N, File]).

read_pcap_stream(In, Acc, Total) :-
    read_line_to_string(In, Line),
    ( Line == end_of_file ->
        Total = Acc
    ;
      ( Line \= "", parse_pcap_line(Line) -> Acc1 is Acc + 1 ; Acc1 = Acc ),
      read_pcap_stream(In, Acc1, Total)
    ).

parse_pcap_line(Line) :-
    split_string(Line, ",", "", Parts),
    length(Parts, Len), Len >= 6,
    nth1(1, Parts, TsS),
    nth1(2, Parts, SrcS),
    nth1(3, Parts, DstS),
    nth1(4, Parts, TcpS),
    nth1(5, Parts, UdpS),
    nth1(6, Parts, LenS),
    SrcS \= "", DstS \= "",          % skip non-IP frames (ARP, STP, etc.)
    number_string(TsF, TsS),
    Ts is truncate(TsF),
    atom_string(Src, SrcS),
    atom_string(Dst, DstS),
    ( TcpS \= "", number_string(Port, TcpS) -> Proto = tcp
    ; UdpS \= "", number_string(Port, UdpS) -> Proto = udp
    ; Port = 0, Proto = other
    ),
    ( LenS \= "", number_string(Bytes, LenS) -> true ; Bytes = 0 ),
    assertz(connection(Ts, Src, Dst, Port, Bytes, Proto)).

%% ===========================================================
%%  Address classification
%% ===========================================================

%% RFC-1918 private ranges
is_internal(IP) :-
    atom(IP),
    atom_string(IP, S),
    ( sub_string(S, 0, _, _, "192.168.") -> true
    ; sub_string(S, 0, _, _, "10.")      -> true
    ; is_172_private(S)
    ), !.

is_172_private(S) :-
    sub_string(S, 0, 4, _, "172."),
    sub_string(S, 4, _, _, Tail),
    split_string(Tail, ".", "", [OStr | _]),
    number_string(Oct, OStr),
    Oct >= 16, Oct =< 31.

%% Off-hours: 00:00–07:59 or 18:00–23:59 UTC
is_off_hours(Ts) :-
    number(Ts),
    Hour is (round(Ts) mod 86400) // 3600,
    ( Hour < 8 ; Hour >= 18 ), !.

%% ===========================================================
%%  Connection log loader
%%
%%  Format (one record per line; lines starting with # are comments):
%%    unix_timestamp,src_ip,dst_ip,dst_port,bytes_out,protocol[,verdict]
%%
%%  Example:
%%    1715248800,192.168.1.100,10.0.0.5,22,1024,tcp,blocked
%% ===========================================================

load_connection_log(File) :-
    retractall(connection(_, _, _, _, _, _)),
    setup_call_cleanup(
        open(File, read, In),
        read_conn_stream(In, 0, N),
        close(In)
    ),
    format("[+] Loaded ~w connection record(s) from '~w'~n", [N, File]).

read_conn_stream(In, Acc, Total) :-
    read_line_to_string(In, Line),
    ( Line == end_of_file ->
        Total = Acc
    ;
      ( blank_or_comment(Line) -> Acc1 = Acc
      ; parse_conn_csv(Line)   -> Acc1 is Acc + 1
      ; format(user_error, "[!] Skipping malformed connection line: ~w~n", [Line]),
        Acc1 = Acc
      ),
      read_conn_stream(In, Acc1, Total)
    ).

parse_conn_csv(Line) :-
    split_string(Line, ",", " \t\r", Parts),
    Parts = [TsS, SrcS, DstS, PortS, BytesS, ProtoS | _],
    number_string(Ts,    TsS),
    number_string(Port,  PortS),
    number_string(Bytes, BytesS),
    atom_string(Src,   SrcS),
    atom_string(Dst,   DstS),
    atom_string(Proto, ProtoS),
    assertz(connection(Ts, Src, Dst, Port, Bytes, Proto)).

%% ===========================================================
%%  Auth log loader
%%
%%  Accepts two formats automatically:
%%
%%  CSV:
%%    unix_timestamp,src_ip,username,result
%%    result ∈ { failed, success, invalid_user }
%%    Example: 1715248800,203.0.113.5,root,failed
%%
%%  OpenSSH syslog:
%%    Mon DD HH:MM:SS host sshd[N]: Failed password for root from 1.2.3.4 port 22 ssh2
%%    Mon DD HH:MM:SS host sshd[N]: Accepted password for alice from 1.2.3.4 port 22 ssh2
%%    Mon DD HH:MM:SS host sshd[N]: Invalid user guest from 1.2.3.4 port 22
%% ===========================================================

load_auth_log(File) :-
    retractall(login_attempt(_, _, _, _)),
    setup_call_cleanup(
        open(File, read, In),
        read_auth_stream(In, 0, N),
        close(In)
    ),
    format("[+] Loaded ~w auth event(s) from '~w'~n", [N, File]).

read_auth_stream(In, Acc, Total) :-
    read_line_to_string(In, Line),
    ( Line == end_of_file ->
        Total = Acc
    ;
      ( blank_or_comment(Line)  -> Acc1 = Acc
      ; parse_auth_csv(Line)    -> Acc1 is Acc + 1
      ; parse_syslog_ssh(Line)  -> Acc1 is Acc + 1
      ; Acc1 = Acc   % non-SSH syslog lines silently skipped
      ),
      read_auth_stream(In, Acc1, Total)
    ).

parse_auth_csv(Line) :-
    split_string(Line, ",", " \t\r", [TsS, SrcS, UserS, ResS]),
    number_string(Ts, TsS),
    atom_string(Src,    SrcS),
    atom_string(User,   UserS),
    atom_string(Result, ResS),
    member(Result, [failed, success, invalid_user]),
    assertz(login_attempt(Ts, Src, User, Result)).

%% Syslog SSH parser
parse_syslog_ssh(Line) :-
    nonempty_tokens(Line, [MonS, DayS, TimeS | _]),
    atom_string(MonA, MonS),
    month_num(MonA, MonN),
    number_string(DayN, DayS),
    time_secs(TimeS, TimeSec),
    %% Approximate timestamp — relative ordering correct, year ignored
    Ts is MonN * 2592000 + DayN * 86400 + TimeSec,
    syslog_ssh_event(Line, User, Src, Result),
    assertz(login_attempt(Ts, Src, User, Result)).

syslog_ssh_event(Line, User, Src, failed) :-
    sub_string(Line, _, _, _, "Failed password for"),
    ( sub_string(Line, _, _, _, "invalid user") ->
        ssh_extract(Line, "Failed password for invalid user ", User, Src)
    ;
        ssh_extract(Line, "Failed password for ", User, Src)
    ).

syslog_ssh_event(Line, User, Src, success) :-
    sub_string(Line, _, _, _, "Accepted password for"),
    ssh_extract(Line, "Accepted password for ", User, Src).

syslog_ssh_event(Line, User, Src, invalid_user) :-
    sub_string(Line, _, _, _, "Invalid user "),
    ssh_extract(Line, "Invalid user ", User, Src).

%% ssh_extract(+Line, +Prefix, -User, -SrcIP)
%% Locates "<Prefix><user> from <ip>" anywhere in Line.
ssh_extract(Line, Prefix, User, Src) :-
    string_length(Prefix, PLen),
    sub_string(Line, Before, PLen, _, Prefix),
    Start is Before + PLen,
    sub_string(Line, Start, _, 0, Rest),
    split_string(Rest, " ", "", [UserS, "from", SrcS | _]),
    atom_string(User, UserS),
    atom_string(Src,  SrcS).

month_num('Jan',1).  month_num('Feb',2).  month_num('Mar',3).
month_num('Apr',4).  month_num('May',5).  month_num('Jun',6).
month_num('Jul',7).  month_num('Aug',8).  month_num('Sep',9).
month_num('Oct',10). month_num('Nov',11). month_num('Dec',12).

time_secs(TimeS, Secs) :-
    split_string(TimeS, ":", "", [H, M, S]),
    maplist(number_string, [Hi, Mi, Si], [H, M, S]),
    Secs is Hi * 3600 + Mi * 60 + Si.

nonempty_tokens(Str, Toks) :-
    split_string(Str, " ", "", All),
    include([T]>>(T \= ""), All, Toks).

blank_or_comment("").
blank_or_comment(L) :- sub_string(L, 0, 1, _, "#").

%% ===========================================================
%%  Detection Rules
%%
%%  threat(+Type, +Key, -Evidence)
%%    Type     — atom identifying the attack class
%%    Key      — term identifying the actor/victim (used for deduplication)
%%    Evidence — structured term explaining why the rule fired
%%
%%  Adding a new detection rule is as simple as adding a new
%%  threat/3 clause — the reporting and deduplication are automatic.
%% ===========================================================

%% ── Port Scan ───────────────────────────────────────────────
%% One source touches >= threshold distinct ports on the same
%% destination within a sliding time window.
threat(port_scan, src(Src)-dst(Dst), ports_in_window(Count, Ports)) :-
    threshold(port_scan_count,  MinPorts),
    threshold(port_scan_window, Window),
    connection(Anchor, Src, Dst, _, _, _),
    aggregate_all(set(Port),
        ( connection(T, Src, Dst, Port, _, _),
          T >= Anchor, T =< Anchor + Window ),
        Ports),
    length(Ports, Count),
    Count >= MinPorts.

%% ── Brute Force ─────────────────────────────────────────────
%% Repeated failed auth attempts against the same account from
%% the same source within a time window.
threat(brute_force, src(Src)-user(User), attempts(Count)) :-
    threshold(brute_force_count,  Min),
    threshold(brute_force_window, Window),
    login_attempt(Anchor, Src, User, failed),
    aggregate_all(count,
        ( login_attempt(T, Src, User, failed),
          T >= Anchor, T =< Anchor + Window ),
        Count),
    Count >= Min.

%% ── Data Exfiltration ───────────────────────────────────────
%% An internal host sends an abnormally large volume of data to
%% an external host in a single connection.
threat(data_exfiltration, src(Src)-dst(Dst),
       evidence(bytes(Bytes), port(Port), off_hours(OffHours))) :-
    threshold(exfil_bytes, MinBytes),
    connection(Ts, Src, Dst, Port, Bytes, _),
    is_internal(Src),
    \+ is_internal(Dst),
    Bytes >= MinBytes,
    ( is_off_hours(Ts) -> OffHours = yes ; OffHours = no ).

%% ── Lateral Movement ────────────────────────────────────────
%% An internal host connects to many distinct internal peers —
%% consistent with worm spread or post-compromise reconnaissance.
threat(lateral_movement, src(Src), contacted_hosts(Count, Targets)) :-
    threshold(lateral_hosts, Min),
    connection(_, Src, _, _, _, _),   % generate candidate source IPs
    is_internal(Src),
    aggregate_all(set(Dst),
        ( connection(_, Src, Dst, _, _, _),
          is_internal(Dst), Dst \= Src ),
        Targets),
    length(Targets, Count),
    Count >= Min.

%% ── Blacklisted IP ──────────────────────────────────────────
%% Any traffic to or from a known malicious IP address.
threat(blacklist_hit, ip(BadIP), traffic(Dir)) :-
    blacklisted_ip(BadIP),
    ( connection(_, BadIP, Dst, Port, _, _),
        Dir = inbound(from(BadIP), to(Dst), port(Port))
    ; connection(_, Src, BadIP, Port, _, _),
        Dir = outbound(from(Src), to(BadIP), port(Port))
    ).

%% ===========================================================
%%  Deduplication
%%  threat/3 can match the same (Type, Key) multiple times when
%%  the sliding window anchors on different events.  Collapse each
%%  unique pair to one alert.
%% ===========================================================

unique_threats(Threats) :-
    findall(Type-Key, threat(Type, Key, _), Raw),
    list_to_set(Raw, Pairs),
    maplist([Type-Key, threat(Type, Key, Ev)]>>(
                once(threat(Type, Key, Ev))
            ), Pairs, Threats).

%% ===========================================================
%%  Report
%% ===========================================================

analyze :-
    format("~n+==========================================+~n"),
    format("|   Network Threat Detection Report       |~n"),
    format("+==========================================+~n~n"),
    report_summary,
    format("~n-- Threat Analysis --------------------------------~n~n"),
    unique_threats(Threats),
    ( Threats = [] ->
        format("  [OK] No threats detected.~n")
    ;
        length(Threats, N),
        format("  [!] ~w threat(s) detected:~n~n", [N]),
        maplist(print_threat, Threats)
    ),
    format("---------------------------------------------------~n").

report_summary :-
    aggregate_all(count, connection(_, _, _, _, _, _), ConnN),
    aggregate_all(count, login_attempt(_, _, _, _),    AuthN),
    aggregate_all(count, blacklisted_ip(_),            BLN),
    format("  Connections analysed : ~w~n", [ConnN]),
    format("  Auth events analysed : ~w~n", [AuthN]),
    format("  Blacklisted IPs      : ~w~n", [BLN]).

severity_label(port_scan,        '[HIGH    ]').
severity_label(brute_force,      '[HIGH    ]').
severity_label(data_exfiltration,'[CRITICAL]').
severity_label(lateral_movement, '[HIGH    ]').
severity_label(blacklist_hit,    '[CRITICAL]').

print_threat(threat(Type, Key, Evidence)) :-
    severity_label(Type, Sev),
    format("  ~w ~w~n", [Sev, Type]),
    format("     Target   : ~q~n", [Key]),
    format("     Evidence : ~q~n~n", [Evidence]).

%% ===========================================================
%%  Command-line entry point
%%  $ swipl -g main network_monitor.pl -- connections.log auth.log
%% ===========================================================

main :-
    current_prolog_flag(argv, [ConnLog, AuthLog | _]),
    !,
    load_connection_log(ConnLog),
    load_auth_log(AuthLog),
    analyze.
main :-
    format(user_error,
        "Usage: swipl -g main network_monitor.pl -- <connections.log> <auth.log>~n", []).
