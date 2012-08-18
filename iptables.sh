#!/bin/bash

###########################################################
# このスクリプトの特徴
#
# 受信・通過については基本的に破棄し、ホワイトリストで許可するものを指定する。
# 送信については基本的に許可する。ただし、サーバが踏み台になり外部のサーバに迷惑をかける可能性があるので、
# 心配な場合は、送信も受信同様に基本破棄・ホワイトリストで許可するように書き換えると良い。
###########################################################


###########################################################
# 用語の統一
# わかりやすさのためルールとコメントの用語を以下に統一する
# ACCEPT : 許可
# DROP   : 破棄
# REJECT : 拒否
###########################################################

# パス
PATH=/sbin:/usr/sbin:/bin:/usr/bin

###########################################################
# IPの定義
# 必要に応じて定義する。定義しなくても動作する。
###########################################################

# 内部ネットワークとして許可する範囲
# LOCAL_NET="xxx.xxx.xxx.xxx/xx"
 
# 外部ネットワークとして許可する範囲
# GLOBAL_NET="xxx.xxx.xxx.xxx/xx"

# ZabbixサーバーIP
# ZABBIX_IP="xxx.xxx.xxx.xxx"

# 全てのIPを表す設定を定義
# ANY="0.0.0.0/0"

# 信頼可能ホスト(配列)
# ALLOW_HOSTS=(
# 	"xxx.xxx.xxx.xxx"
# 	"xxx.xxx.xxx.xxx"
# 	"xxx.xxx.xxx.xxx"
# )

# 拒否リスト(配列)
# DENY_HOSTS=(
# 	"xxx.xxx.xxx.xxx"
# 	"xxx.xxx.xxx.xxx"
# 	"xxx.xxx.xxx.xxx"
# )

###########################################################
# ポート定義
###########################################################

SSH=22
FTP=20,21
DNS=53
SMTP=25,465,587
POP3=110,995
IMAP=143,993
HTTP=80,443
IDENT=113
NTP=123
MYSQL=3306
NET_BIOS=135,137,138,139,445
DHCP=67,68

###########################################################
# iptablesの初期化
# すべてのルールを削除
###########################################################
iptables -F # テーブル初期化
iptables -X # チェーンを削除
iptables -Z # パケットカウンタ・バイトカウンタをクリア

# ポリシーの初期化
# 「ポリシーの決定」でDROPにおきかえる
iptables -P INPUT   ACCEPT
iptables -P OUTPUT  ACCEPT
iptables -P FORWARD ACCEPT
 
###########################################################
# 信頼可能なホストは許可
###########################################################

# ローカルホスト
# lo はローカルループバックのことで自分自身のホストを指す
iptables -A INPUT  -i lo -j ACCEPT # SELF -> SELF
iptables -A OUTPUT -o lo -j ACCEPT # SELF -> SELF

# ローカルネットワーク
# $LOCAL_NET が設定されていれば LAN上の他のサーバとのやり取りを許可する
if [ "$LOCAL_NET" ]
then
	iptables -A INPUT  -p tcp -s $LOCAL_NET -j ACCEPT # LOCAL_NET -> SELF
	iptables -A OUTPUT -p tcp -d $LOCAL_NET -j ACCEPT # SELF -> LOCAL_NET
fi

# 信頼可能ホスト
# $ALLOW_HOSTS が設定されていれば そのホストとのやり取りを許可する
if [ "${ALLOW_HOSTS[@]}" ]
then
	for allow_host in ${ALLOW_HOSTS[@]}
	do
		iptables -A INPUT  -p tcp -s $allow_host -j ACCEPT # allow_host -> SELF
		iptables -A OUTPUT -p tcp -d $allow_host -j ACCEPT # SELF -> allow_host
	done
fi

###########################################################
# 拒否IPからのアクセスは破棄
###########################################################
if [ "${DENY_HOSTS[@]}" ]
then
	for host in ${DENY_HOSTS[@]}
	do
		iptables -A INPUT -s $ip -m limit --limit 1/s -j LOG --log-prefix "[deny host] "
		iptables -A INPUT -s $ip -j DROP
	done
fi

###########################################################
# セッション確立後のパケット疎通は許可
###########################################################
iptables -A INPUT  -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT

###########################################################
# 攻撃対策: Stealth Scan
###########################################################
# すべてのTCPセッションがSYNで始まらないものを破棄
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j LOG --log-prefix "[stealth scan attack] "
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
 
###########################################################
# 攻撃対策: Ping of Death
###########################################################
# 1秒間に10回を超えるpingを破棄
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 10 -j LOG --log-prefix "[ping of death attack] "
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 10 -j DROP

###########################################################
# 攻撃対策: SYN Flood Attack
# この対策に加えて Syn Cookie を有効にすべし。
###########################################################
iptables -N SYN_FLOOD # "SYN_FLOOD" という名前でチェーンを作る
iptables -A SYN_FLOOD -p tcp --syn \
         -m hashlimit \                     # ホストごとに制限するため limit ではなく hashlimit を利用する
         --hashlimit 200/s \                # 秒間に200接続を上限にする
         --hashlimit-burst 3 \              # 上記の上限を超えた接続が3回連続であれば制限がかかる
         --hashlimit-htable-expire 300000 \ # 管理テーブル中のレコードの有効期間（単位：ms
         --hashlimit-mode srcip \           # 送信元アドレスでリクエスト数を管理する
         --hashlimit-name t_SYN_FLOOD \     # /proc/net/ipt_hashlimit に保存されるハッシュテーブル名
         -j RETURN                          # 制限以内であれば、親チェーンに戻る

# 制限を超えたSYNパケットを破棄
iptables -A SYN_FLOOD -j LOG --log-prefix "[SYN flood attack] "
iptables -A SYN_FLOOD -j DROP

# SYNパケットは "SYN_FLOOD" チェーンへジャンプ
iptables -A INPUT -p tcp --syn -j SYN_FLOOD

###########################################################
# 攻撃対策: HTTP DoS/DDoS Attack
###########################################################
iptables -N HTTP_DOS # "HTTP_DOS" という名前でチェーンを作る
iptables -A HTTP_DOS -p tcp --dport $HTTP \
         -m hashlimit \                     # ホストごとに制限するため limit ではなく hashlimit を利用する
         --hashlimit 1/s \                  # 秒間1接続を上限とする
         --hashlimit-burst 100 \            # 上記の上限を100回連続で超えると制限がかかる
         --hashlimit-htable-expire 300000 \ # 管理テーブル中のレコードの有効期間（単位：ms
         --hashlimit-mode srcip \           # 送信元アドレスでリクエスト数を管理する
         --hashlimit-name t_HTTP_DOS \      # /proc/net/ipt_hashlimit に保存されるハッシュテーブル名
         -j RETURN                          # 制限以内であれば、親チェーンに戻る

# 制限を超えた接続を破棄
iptables -A HTTP_DOS -j LOG --log-prefix "[HTTP DoS attack] "
iptables -A HTTP_DOS -j DROP

# HTTPへのパケットは "HTTP_DOS" チェーンへジャンプ
iptables -A INPUT -p tcp --dport $HTTP -j HTTP_DOS

###########################################################
# 攻撃対策: IDENT port probe
# identを利用し攻撃者が将来の攻撃に備えるため、あるいはユーザーの
# システムが攻撃しやすいかどうかを確認するために、ポート調査を実行
# する可能性があります。
# DROP ではメールサーバ等のレスポンス低下になるため REJECTする
###########################################################
iptables -A INPUT -p tcp --dport $IDENT -j REJECT --reject-with tcp-reset

###########################################################
# 攻撃対策: SSH Brute Force
# SSHはパスワード認証を利用しているサーバの場合、パスワード総当り攻撃に備える。
# 1分間に5回しか接続トライをできないようにする。
# SSHクライアント側が再接続を繰り返すのを防ぐためDROPではなくREJECTにする。
# SSHサーバがパスワード認証ONの場合、以下をアンコメントアウトする
###########################################################
# iptables -A INPUT -p tcp --syn --dport $SSH -m recent --name ssh_attack --set
# iptables -A INPUT -p tcp --syn --dport $SSH -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 5 -j LOG --log-prefix "[SSH Brute Force] "
# iptables -A INPUT -p tcp --syn --dport $SSH -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 5 -j REJECT --reject-with tcp-reset

###########################################################
# 攻撃対策: FTP Brute Force
# FTPはパスワード認証のため、パスワード総当り攻撃に備える。
# 1分間に5回しか接続トライをできないようにする。
# FTPクライアント側が再接続を繰り返すのを防ぐためDROPではなくREJECTにする。
# FTPサーバを立ち上げている場合、以下をアンコメントアウトする
###########################################################
# iptables -A INPUT -p tcp --syn --dport $FTP -m recent --name ftp_attack --set
# iptables -A INPUT -p tcp --syn --dport $FTP -m recent --name ftp_attack --rcheck --seconds 60 --hitcount 5 -j LOG --log-prefix "[FTP Brute Force] "
# iptables -A INPUT -p tcp --syn --dport $FTP -m recent --name ftp_attack --rcheck --seconds 60 --hitcount 5 -j REJECT --reject-with tcp-reset

###########################################################
# 全ホスト(ブロードキャストアドレス、マルチキャストアドレス)宛パケットは破棄
###########################################################
iptables -A INPUT -d 192.168.1.255   -j LOG --log-prefix "[drop broadcast] "
iptables -A INPUT -d 192.168.1.255   -j DROP
iptables -A INPUT -d 255.255.255.255 -j LOG --log-prefix "[drop broadcast] "
iptables -A INPUT -d 255.255.255.255 -j DROP

###########################################################
# 全ホスト(ANY)からの入力許可
###########################################################

# ICMP: ping に応答する設定
iptables -A INPUT -p icmp -j ACCEPT # ANY -> SELF

# HTTP, HTTPS
iptables -A INPUT -p tcp --dport $HTTP -j ACCEPT # ANY -> SELF

# FTP
# iptables -A INPUT -p tcp --dport $FTP -j ACCEPT # ANY -> SELF

# DNS
# iptables -A INPUT -p tcp --sport $DNS -j ACCEPT # ANY -> SELF
# iptables -A INPUT -p udp --sport $DNS -j ACCEPT # ANY -> SELF

# SMTP
# iptables -A INPUT -p tcp --sport $SMTP -j ACCEPT # ANY -> SELF

# POP3
# iptables -A INPUT -p tcp --sport $POP3 -j ACCEPT # ANY -> SELF

# IMAP
# iptables -A INPUT -p tcp --sport $IMAP -j ACCEPT # ANY -> SELF

###########################################################
# ローカルネットワークからの入力許可
###########################################################

if [ "$LOCAL_NET" ]
then
	# SSH
	iptables -A INPUT -p tcp -s $LOCAL_NET --dport $SSH -j ACCEPT # LOCALNET -> SELF
	
	# FTP
	iptables -A INPUT -p tcp -s $LOCAL_NET -m multiport --dport $FTP -j ACCEPT # LOCALNET -> SELF

	# MySQL
	iptables -A INPUT -p tcp -s $LOCAL_NET --dport $MYSQL -j ACCEPT # LOCALNET -> SELF
fi

###########################################################
# 特定ホストからの入力許可
###########################################################

if [ "$ZABBIX_IP" ]
then
	# Zabbix関連を許可
	iptables -A INPUT -p tcp -s $ZABBIX_IP --dport 10050 -j ACCEPT # Zabbix -> SELF
fi

###########################################################
# それ以外
# 上記のルールにも当てはまらなかったものはロギングして破棄
###########################################################
iptables -A INPUT  -j LOG --log-prefix "[drop] "
iptables -A INPUT  -j DROP
 
###########################################################
# ポリシーの決定
# すべてのパケットを破棄(DROP)する。
# すべての穴をふさいでから必要なポートを空けていくのが良い。
###########################################################
iptables -P INPUT   DROP
iptables -P OUTPUT  ACCEPT
iptables -P FORWARD DROP

###########################################################
# 設定の保存と反映
###########################################################
/etc/init.d/iptables save
/etc/init.d/iptables restart