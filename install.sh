#!/bin/bash

red='\e[91m'
green='\e[92m'
yellow='\e[93m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'
_red() { echo -e ${red}$*${none}; }
_green() { echo -e ${green}$*${none}; }
_yellow() { echo -e ${yellow}$*${none}; }
_magenta() { echo -e ${magenta}$*${none}; }
_cyan() { echo -e ${cyan}$*${none}; }

# Root
[[ $(id -u) != 0 ]] && echo -e "\n ${red}root ${none}계정으로 실행해 주세요.${yellow}~(^_^) ${none}\n" && exit 1

cmd="apt-get"

sys_bit=$(uname -m)

case $sys_bit in
i[36]86)
	v2ray_bit="32"
	caddy_arch="386"
	;;
x86_64)
	v2ray_bit="64"
	caddy_arch="amd64"
	;;
*armv6*)
	v2ray_bit="arm"
	caddy_arch="arm6"
	;;
*armv7*)
	v2ray_bit="arm"
	caddy_arch="arm7"
	;;
*aarch64* | *armv8*)
	v2ray_bit="arm64"
	caddy_arch="arm64"
	;;
*)
	echo -e " 
	이 ${red}스크립트는${none} 현재 시스템을 지원하지 않습니다. ${yellow}(-_-) ${none}

	참고: Ubuntu 16+ / Debian 8+ / CentOS 7+ 시스템만 지원합니다.
	" && exit 1
	;;
esac

# 笨笨的检测方法
if [[ $(command -v apt-get) || $(command -v yum) ]] && [[ $(command -v systemctl) ]]; then

	if [[ $(command -v yum) ]]; then

		cmd="yum"

	fi

else

	echo -e " 
	이 ${red}스크립트는${none} 현재 시스템을 지원하지 않습니다. ${yellow}(-_-) ${none}

	참고: Ubuntu 16+ / Debian 8+ / CentOS 7+ 시스템만 지원합니다.
	" && exit 1

fi

uuid=$(cat /proc/sys/kernel/random/uuid)
old_id="e55c8d17-2cf3-b21a-bcf1-eeacb011ed79"
v2ray_server_config="/etc/v2ray/config.json"
v2ray_client_config="/etc/v2ray/szkorean_v2ray_config.json"
backup="/etc/v2ray/szkorean_v2ray_backup.conf"
_v2ray_sh="/usr/local/sbin/v2ray"
systemd=true
# _test=true

transport=(
	TCP
	TCP_HTTP
	WebSocket
	"WebSocket + TLS"
	HTTP/2
	mKCP
	mKCP_utp
	mKCP_srtp
	mKCP_wechat-video
	mKCP_dtls
	mKCP_wireguard
	QUIC
	QUIC_utp
	QUIC_srtp
	QUIC_wechat-video
	QUIC_dtls
	QUIC_wireguard
	TCP_dynamicPort
	TCP_HTTP_dynamicPort
	WebSocket_dynamicPort
	mKCP_dynamicPort
	mKCP_utp_dynamicPort
	mKCP_srtp_dynamicPort
	mKCP_wechat-video_dynamicPort
	mKCP_dtls_dynamicPort
	mKCP_wireguard_dynamicPort
	QUIC_dynamicPort
	QUIC_utp_dynamicPort
	QUIC_srtp_dynamicPort
	QUIC_wechat-video_dynamicPort
	QUIC_dtls_dynamicPort
	QUIC_wireguard_dynamicPort
)

ciphers=(
	aes-128-cfb
	aes-256-cfb
	chacha20
	chacha20-ietf
	aes-128-gcm
	aes-256-gcm
	chacha20-ietf-poly1305
)

_load() {
	local _dir="/etc/v2ray/kikunae77/v2ray/src/"
	. "${_dir}$@"
}
_sys_timezone() {
	IS_OPENVZ=
	if hostnamectl status | grep -q openvz; then
		IS_OPENVZ=1
	fi

	echo
	timedatectl set-timezone Asia/Shanghai
	timedatectl set-ntp true
	echo "서버를 Asia/Shanghai 시간으로 설정하고 systemd-timesyncd을 통해 자동으로 시간이 동기화 되도록 설정하였습니다."
	echo

	if [[ $IS_OPENVZ ]]; then
		echo
		echo -e "서버 환경이 ${yellow}Openvz${none}입니다. ${yellow}v2ray mkcp${none}프로토콜 사용을 추천합니다."
		echo -e "주의：${yellow}Openvz${none} 시스템은 시간을 임의로 설정하고 동기화할 수 없습니다."
		echo -e "만약 서버 시간이 실제 시간과${yellow}90초${none} 이상 차이나는 경우, v2ray가 정상적인 통신을 할 수 없습니다. VPS 운영업체에 시간 조정을 별도로 요청하세요."
	fi
}

_sys_time() {
	echo -e "\n서버 시간：${yellow}"
	timedatectl status | sed -n '1p;4p'
	echo -e "${none}"
	[[ $IS_OPENV ]] && pause
}
v2ray_config() {
	# clear
	echo
	while :; do
		echo -e " "$yellow"V2Ray"$none" 프로토콜 선택 [${magenta}1-${#transport[*]}$none]"
		echo
		for ((i = 1; i <= ${#transport[*]}; i++)); do
			Stream="${transport[$i - 1]}"
			if [[ "$i" -le 9 ]]; then
				# echo
				echo -e "$yellow  $i. $none${Stream}"
			else
				# echo
				echo -e "$yellow $i. $none${Stream}"
			fi
		done
		echo
		echo "참고1: [dynamicPort] 포함시 동적포트가 시작됩니다.."
		echo "참고2: [utp | srtp | wechat-video | dtls | wireguard] 는 각각 [BT 다운로드 | 영상통화 | 위챗영상통화 | DTLS 1.2 패킷 | WireGuard 패킷]으로 위장됩니다."
		echo
		read -p "$(echo -e "(기본 프로토콜: ${cyan}TCP$none)"):" v2ray_transport
		[ -z "$v2ray_transport" ] && v2ray_transport=1
		case $v2ray_transport in
		[1-9] | [1-2][0-9] | 3[0-2])
			echo
			echo
			echo -e "$yellow V2Ray 프로토콜  = $cyan${transport[$v2ray_transport - 1]}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac
	done
	v2ray_port_config
}
v2ray_port_config() {
	case $v2ray_transport in
	4 | 5)
		tls_config
		;;
	*)
		local random=$(shuf -i20001-65535 -n1)
		while :; do
			echo -e " "$yellow"V2Ray"$none"가 사용할 포트를 입력해주세요. ["$magenta"1-65535"$none"]"
			read -p "$(echo -e "(기본 포트: ${cyan}${random}$none):")" v2ray_port
			[ -z "$v2ray_port" ] && v2ray_port=$random
			case $v2ray_port in
			[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
				echo
				echo
				echo -e "$yellow V2Ray 포트 = $cyan$v2ray_port$none"
				echo "----------------------------------------------------------------"
				echo
				break
				;;
			*)
				error
				;;
			esac
		done
		if [[ $v2ray_transport -ge 18 ]]; then
			v2ray_dynamic_port_start
		fi
		;;
	esac
}

v2ray_dynamic_port_start() {

	while :; do
		echo -e " "$yellow"V2Ray 동적포트 시작 "$none"범위를 입력하세요 ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(기본 시작 포트: ${cyan}10000$none):")" v2ray_dynamic_port_start_input
		[ -z $v2ray_dynamic_port_start_input ] && v2ray_dynamic_port_start_input=10000
		case $v2ray_dynamic_port_start_input in
		$v2ray_port)
			echo
			echo " V2Ray 포트와 같으면 안됩니다...."
			echo
			echo -e " 기존 V2Ray 포트：${cyan}$v2ray_port${none}"
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			echo
			echo
			echo -e "$yellow V2Ray 동적포트 시작 포트 = $cyan$v2ray_dynamic_port_start_input$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac

	done

	if [[ $v2ray_dynamic_port_start_input -lt $v2ray_port ]]; then
		lt_v2ray_port=true
	fi

	v2ray_dynamic_port_end
}
v2ray_dynamic_port_end() {

	while :; do
		echo -e " "$yellow"V2Ray 동적포트 종료 "$none"범위를 입력하세요. ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(기본 종료 포트: ${cyan}20000$none):")" v2ray_dynamic_port_end_input
		[ -z $v2ray_dynamic_port_end_input ] && v2ray_dynamic_port_end_input=20000
		case $v2ray_dynamic_port_end_input in
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])

			if [[ $v2ray_dynamic_port_end_input -le $v2ray_dynamic_port_start_input ]]; then
				echo
				echo " V2Ray 동적포트 시작 포트와 같거나 작을 수 없습니다."
				echo
				echo -e " 기존 V2Ray 동적포트 시작 포트：${cyan}$v2ray_dynamic_port_start_input${none}"
				error
			elif [ $lt_v2ray_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $v2ray_port ]]; then
				echo
				echo " V2Ray 동적포트 종료 포트는 V2Ray 포트를 포함할 수 없습니다..."
				echo
				echo -e " 기존 V2Ray 포트：${cyan}$v2ray_port${none}"
				error
			else
				echo
				echo
				echo -e "$yellow V2Ray 동적포트 종료 번호 = $cyan$v2ray_dynamic_port_end_input$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi
			;;
		*)
			error
			;;
		esac

	done

}

tls_config() {

	echo
	local random=$(shuf -i20001-65535 -n1)
	while :; do
		echo -e " "$yellow"V2Ray"$none"가 사용할 포트를 입력해 주세요. ["$magenta"1-65535"$none"]，"$magenta"80"$none" 이나 "$magenta"443"$none" 포트는 선택할 없습니다."
		read -p "$(echo -e "(기본 포트: ${cyan}${random}$none):")" v2ray_port
		[ -z "$v2ray_port" ] && v2ray_port=$random
		case $v2ray_port in
		80)
			echo
			echo " 80 번 포트는 사용할 수 없습니다..."
			error
			;;
		443)
			echo
			echo " 443 번 포트는 사용할 수 없습니다..."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			echo
			echo
			echo -e "$yellow V2Ray 포트 = $cyan$v2ray_port$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac
	done

	while :; do
		echo
		echo -e " $magenta정확한 도메인명$none을 입력해주세요. 반드시 정확하게 입력해 주셔야 합니다."
		read -p "(例如：szkorean.net): " domain
		[ -z "$domain" ] && error && continue
		echo
		echo
		echo -e "$yellow 입력한 도메인명 = $cyan$domain$none"
		echo "----------------------------------------------------------------"
		break
	done
	get_ip
	echo
	echo
	echo -e " $magenta$new_domain$none $yellow이 해석된 IP: $cyan$ip$none"
	echo
	echo -e " $magenta$new_domain$none $yellow이 해석된 IP: $cyan$ip$none"
	echo
	echo -e " $magenta$new_domain$none $yellow이 해석된 IP: $cyan$ip$none"
	echo "----------------------------------------------------------------"
	echo

	while :; do

		read -p "$(echo -e "(제대로 해석되었습니까? : [${magenta}Y$none]):") " record
		if [[ -z "$record" ]]; then
			error
		else
			if [[ "$record" == [Yy] ]]; then
				domain_check
				echo
				echo
				echo -e "$yellow 도메인 해석 = ${cyan}정확하게 해석되었습니다.$none"
				echo "----------------------------------------------------------------"
				echo
				break
			else
				error
			fi
		fi

	done

	if [[ $v2ray_transport -ne 5 ]]; then
		auto_tls_config
	else
		caddy=true
		install_caddy_info="켬"
	fi

	if [[ $caddy ]]; then
		path_config_ask
	fi
}
auto_tls_config() {
	echo -e "

		Caddy를 설치하여 자동으로 TLS를 설정합니다.
		
		Nginx 또는 Caddy 이미 설치하였고
		
		$yellow직접 TLS 설정을 할 수 있으면$none
		
		TLS 자동 설정을 켤 필요가 없습니다.
		"
	echo "----------------------------------------------------------------"
	echo

	while :; do

		read -p "$(echo -e "(TLS 자동 설정을 하시겠습니까? : [${magenta}Y/N$none]):") " auto_install_caddy
		if [[ -z "$auto_install_caddy" ]]; then
			error
		else
			if [[ "$auto_install_caddy" == [Yy] ]]; then
				caddy=true
				install_caddy_info="켬"
				echo
				echo
				echo -e "$yellow TLS 자동 설정 = $cyan$install_caddy_info$none"
				echo "----------------------------------------------------------------"
				echo
				break
			elif [[ "$auto_install_caddy" == [Nn] ]]; then
				install_caddy_info="끔"
				echo
				echo
				echo -e "$yellow TLS 자동 설정 = $cyan$install_caddy_info$none"
				echo "----------------------------------------------------------------"
				echo
				break
			else
				error
			fi
		fi

	done
}
path_config_ask() {
	echo
	while :; do
		echo -e "사이트 위장 및 경로 변경을 하시겠습니까? [${magenta}Y/N$none]"
		read -p "$(echo -e "(默认: [${cyan}N$none]):")" path_ask
		[[ -z $path_ask ]] && path_ask="n"

		case $path_ask in
		Y | y)
			path_config
			break
			;;
		N | n)
			echo
			echo
			echo -e "$yellow 사이트 위장 및 경로 수정 = $cyan설정 안함$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac
	done
}
path_config() {
	echo
	while :; do
		echo -e "${magenta}사용할 경로$none를 입력해 주세요. 예) /233blog인 경우 233blog 으로 입력하면 됩니다."
		read -p "$(echo -e "(默认: [${cyan}233blog$none]):")" path
		[[ -z $path ]] && path="233blog"

		case $path in
		*[/$]*)
			echo
			echo -e " 경로에$red / $none나$red $ $none 특수기호를 포함할 수 없습니다.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow 경로 = ${cyan}/${path}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done
	is_path=true
	proxy_site_config
}
proxy_site_config() {
	echo
	while :; do
		echo -e "${magenta}정확한$none ${cyan}사이트 주소$none를 입력하여 ${cyan}사이트를 위장$none하세요. https://liyafly.com으로"
		echo -e "예를 들면... 만약 기존에 설정한 도메인이$green $domain $none인 경우, 위장할 사이트는 https://liyafly.com이 됩니다."
		echo -e "설정한 도메인으로 접속하면... 표시되는 내용은 https://liyafly.com의 내용이 표시됩니다."
		echo -e "Reverse Proxy로 이해하시면 됩니다.."
		echo -e "만약 위장에 성공하지 못하는 경우, v2ray config 으로 위장 사이트를 변경하세요."
		read -p "$(echo -e "(默认: [${cyan}https://liyafly.com$none]):")" proxy_site
		[[ -z $proxy_site ]] && proxy_site="https://liyafly.com"

		case $proxy_site in
		*[#$]*)
			echo
			echo -e "위장할 사이트 주소는$red # $none또는$red $ $none 특수기호를 포함할 수 없습니다... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow 위장할 사이트 주소 = ${cyan}${proxy_site}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done
}

blocked_hosts() {
	echo
	while :; do
		echo -e "광고차단을 켜시겠습니까?(성능에 영향 있음) [${magenta}Y/N$none]"
		read -p "$(echo -e "(기본값 [${cyan}N$none]):")" blocked_ad
		[[ -z $blocked_ad ]] && blocked_ad="n"

		case $blocked_ad in
		Y | y)
			blocked_ad_info="켬"
			ban_ad=true
			echo
			echo
			echo -e "$yellow 광고차단 = $cyan켬$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		N | n)
			blocked_ad_info="끔"
			echo
			echo
			echo -e "$yellow 광고차단 = $cyan끔$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac
	done
}
shadowsocks_config() {

	echo

	while :; do
		echo -e " ${yellow}Shadowsocks${none}를 설정하겠습니까? [${magenta}Y/N$none]"
		read -p "$(echo -e "(기본값  [${cyan}N$none]):") " install_shadowsocks
		[[ -z "$install_shadowsocks" ]] && install_shadowsocks="n"
		if [[ "$install_shadowsocks" == [Yy] ]]; then
			echo
			shadowsocks=true
			shadowsocks_port_config
			break
		elif [[ "$install_shadowsocks" == [Nn] ]]; then
			break
		else
			error
		fi

	done

}

shadowsocks_port_config() {
	local random=$(shuf -i20001-65535 -n1)
	while :; do
		echo -e " "$yellow"Shadowsocks"$none" 포트를 입력하세요 ["$magenta"1-65535"$none"]，"$yellow"V2Ray"$none" 포트와 달라야 합니다."
		read -p "$(echo -e "(기본 포트: ${cyan}${random}$none):") " ssport
		[ -z "$ssport" ] && ssport=$random
		case $ssport in
		$v2ray_port)
			echo
			echo " V2Ray 포트와 달라야 합니다...."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $v2ray_transport == [45] ]]; then
				local tls=ture
			fi
			if [[ $tls && $ssport == "80" ]] || [[ $tls && $ssport == "443" ]]; then
				echo
				echo -e " "$green"WebSocket + TLS $none및$green HTTP/2"$none" 전송 프로토콜이 사용중인 포트입니다."
				echo
				echo -e " "$magenta"80"$none" 및 "$magenta"443"$none" 포트는 선택 불가능합니다."
				error
			elif [[ $v2ray_dynamic_port_start_input == $ssport || $v2ray_dynamic_port_end_input == $ssport ]]; then
				local multi_port="${v2ray_dynamic_port_start_input} - ${v2ray_dynamic_port_end_input}"
				echo
				echo " 죄송합니다. 이 포트와 V2Ray 동적포트가 충돌합니다. 기존 V2Ray 동적포트 범위：$multi_port"
				error
			elif [[ $v2ray_dynamic_port_start_input -lt $ssport && $ssport -le $v2ray_dynamic_port_end_input ]]; then
				local multi_port="${v2ray_dynamic_port_start_input} - ${v2ray_dynamic_port_end_input}"
				echo
				echo " 죄송합니다. 이 포트와 V2Ray 동적포트가 충돌합니다. 기존 V2Ray 동적포트 범위：$multi_port"
				error
			else
				echo
				echo
				echo -e "$yellow Shadowsocks 포트 = $cyan$ssport$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi
			;;
		*)
			error
			;;
		esac

	done

	shadowsocks_password_config
}
shadowsocks_password_config() {

	while :; do
		echo -e " "$yellow"Shadowsocks"$none" 비밀번호를 입력해 주세요."
		read -p "$(echo -e "(기본 비번: ${cyan}233blog.com$none)"): " sspass
		[ -z "$sspass" ] && sspass="233blog.com"
		case $sspass in
		*[/$]*)
			echo
			echo -e " $red / $none또는$red $ $none 특수기호는 비번에 포함시킬 수 없습니다.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow Shadowsocks 비밀번호 = $cyan$sspass$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac

	done

	shadowsocks_ciphers_config
}
shadowsocks_ciphers_config() {

	while :; do
		echo -e " "$yellow"Shadowsocks"$none" 암호화 프로토콜을 선택하세요. [${magenta}1-${#ciphers[*]}$none]"
		for ((i = 1; i <= ${#ciphers[*]}; i++)); do
			ciphers_show="${ciphers[$i - 1]}"
			echo
			echo -e "$yellow $i. $none${ciphers_show}"
		done
		echo
		read -p "$(echo -e "(기본 암호화 프로토콜: ${cyan}${ciphers[6]}$none)"):" ssciphers_opt
		[ -z "$ssciphers_opt" ] && ssciphers_opt=7
		case $ssciphers_opt in
		[1-7])
			ssciphers=${ciphers[$ssciphers_opt - 1]}
			echo
			echo
			echo -e "$yellow Shadowsocks 암호화 프로토콜 = $cyan${ssciphers}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac

	done
	pause
}

install_info() {
	clear
	echo
	echo " ....설치 준비 중입니다...설정이 정확한지 확인해 주세요..."
	echo
	echo "---------- 설치 정보 -------------"
	echo
	echo -e "$yellow V2Ray 프로토콜 = $cyan${transport[$v2ray_transport - 1]}$none"

	if [[ $v2ray_transport == [45] ]]; then
		echo
		echo -e "$yellow V2Ray 포트 = $cyan$v2ray_port$none"
		echo
		echo -e "$yellow 도메인명 = $cyan$domain$none"
		echo
		echo -e "$yellow 도메인 해석 = ${cyan}도메인 해석이 정확한 것으로 확인됨$none"
		echo
		echo -e "$yellow TLS 자동 설정 = $cyan$install_caddy_info$none"

		if [[ $ban_ad ]]; then
			echo
			echo -e "$yellow 광고 차단 = $cyan$blocked_ad_info$none"
		fi
		if [[ $is_path ]]; then
			echo
			echo -e "$yellow 경로 = ${cyan}/${path}$none"
		fi
	elif [[ $v2ray_transport -ge 18 ]]; then
		echo
		echo -e "$yellow V2Ray 포트 = $cyan$v2ray_port$none"
		echo
		echo -e "$yellow V2Ray 동적포트 범위ㅣ = $cyan${v2ray_dynamic_port_start_input} - ${v2ray_dynamic_port_end_input}$none"

		if [[ $ban_ad ]]; then
			echo
			echo -e "$yellow 광고 차단 = $cyan$blocked_ad_info$none"
		fi
	else
		echo
		echo -e "$yellow V2Ray 포트 = $cyan$v2ray_port$none"

		if [[ $ban_ad ]]; then
			echo
			echo -e "$yellow 광고 차단 = $cyan$blocked_ad_info$none"
		fi
	fi
	if [ $shadowsocks ]; then
		echo
		echo -e "$yellow Shadowsocks 포트 = $cyan$ssport$none"
		echo
		echo -e "$yellow Shadowsocks 비밀번호 = $cyan$sspass$none"
		echo
		echo -e "$yellow Shadowsocks 암호화 프로토콜 = $cyan${ssciphers}$none"
	else
		echo
		echo -e "$yellow Shadowsocks 설정 여부 = ${cyan}미설정${none}"
	fi
	echo
	echo "---------- END -------------"
	echo
	pause
	echo
}

domain_check() {
	# if [[ $cmd == "yum" ]]; then
	# 	yum install bind-utils -y
	# else
	# 	$cmd install dnsutils -y
	# fi
	# test_domain=$(dig $domain +short)
	test_domain=$(ping $domain -c 1 | grep -oE -m1 "([0-9]{1,3}\.){3}[0-9]{1,3}")
	if [[ $test_domain != $ip ]]; then
		echo
		echo -e "$red 도메인 해석에 오류가 발생했습니다....$none"
		echo
		echo -e " 도메인명 : $yellow$domain$none 이 다음 IP로 해석되지 않습니다. : $cyan$ip$none"
		echo
		echo -e " 도메인명이 해석된 IP: $cyan$test_domain$none"
		echo
		echo "참고...만약 도메인이 Cloudflare 를 사용하는 경우 Status에서 이미지를 클릭하여 회색으로 만드세요."
		echo
		exit 1
	fi
}

install_caddy() {
	# download caddy file then install
	_load download-caddy.sh
	_download_caddy_file
	_install_caddy_service
	caddy_config

}
caddy_config() {
	# local email=$(shuf -i1-10000000000 -n1)
	_load caddy-config.sh

	# systemctl restart caddy
	do_service restart caddy
}

install_v2ray() {
	$cmd update -y
	if [[ $cmd == "apt-get" ]]; then
		$cmd install -y lrzsz git zip unzip curl wget qrencode libcap2-bin dbus
	else
		# $cmd install -y lrzsz git zip unzip curl wget qrencode libcap iptables-services
		$cmd install -y lrzsz git zip unzip curl wget qrencode libcap
	fi
	ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	[ -d /etc/v2ray ] && rm -rf /etc/v2ray
	# date -s "$(curl -sI g.cn | grep Date | cut -d' ' -f3-6)Z"
	_sys_timezone
	_sys_time

	if [[ $local_install ]]; then
		if [[ ! -d $(pwd)/config ]]; then
			echo
			echo -e "$red 설치에 실패했습니다...$none"
			echo
			echo -e " 233v2.com의 V2Ray 설치 및 관리 스크립트가 ${green}$(pwd) $none 경로에 제대로 위치해 있는지 확인하세요."
			echo
			exit 1
		fi
		mkdir -p /etc/v2ray/kikunae77/v2ray
		cp -rf $(pwd)/* /etc/v2ray/kikunae77/v2ray
	else
		pushd /tmp
		git clone https://github.com/kikunae77/v2ray -b "$_gitbranch" /etc/v2ray/kikunae77/v2ray --depth=1
		popd

	fi

	if [[ ! -d /etc/v2ray/kikunae77/v2ray ]]; then
		echo
		echo -e "$red gitgub 연결에 문제가 있습니다...$none"
		echo
		echo -e " 주의.... Git을 설치해 주세요. : ${green}$cmd install -y git $none 명령어 실행 후  스크립트를 다시 실행하세요."
		echo
		exit 1
	fi

	# download v2ray file then install
	_load download-v2ray.sh
	_download_v2ray_file
	_install_v2ray_service
	_mkdir_dir
}

open_port() {
	if [[ $cmd == "apt-get" ]]; then
		if [[ $1 != "multiport" ]]; then

			iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
			iptables -I INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT
			ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
			ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT

			# firewall-cmd --permanent --zone=public --add-port=$1/tcp
			# firewall-cmd --permanent --zone=public --add-port=$1/udp
			# firewall-cmd --reload

		else

			local multiport="${v2ray_dynamic_port_start_input}:${v2ray_dynamic_port_end_input}"
			iptables -I INPUT -p tcp --match multiport --dports $multiport -j ACCEPT
			iptables -I INPUT -p udp --match multiport --dports $multiport -j ACCEPT
			ip6tables -I INPUT -p tcp --match multiport --dports $multiport -j ACCEPT
			ip6tables -I INPUT -p udp --match multiport --dports $multiport -j ACCEPT

			# local multi_port="${v2ray_dynamic_port_start_input}-${v2ray_dynamic_port_end_input}"
			# firewall-cmd --permanent --zone=public --add-port=$multi_port/tcp
			# firewall-cmd --permanent --zone=public --add-port=$multi_port/udp
			# firewall-cmd --reload

		fi
		iptables-save >/etc/iptables.rules.v4
		ip6tables-save >/etc/iptables.rules.v6
		# else
		# 	service iptables save >/dev/null 2>&1
		# 	service ip6tables save >/dev/null 2>&1
	fi
}
del_port() {
	if [[ $cmd == "apt-get" ]]; then
		if [[ $1 != "multiport" ]]; then
			# if [[ $cmd == "apt-get" ]]; then
			iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
			iptables -D INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT
			ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
			ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT
			# else
			# 	firewall-cmd --permanent --zone=public --remove-port=$1/tcp
			# 	firewall-cmd --permanent --zone=public --remove-port=$1/udp
			# fi
		else
			# if [[ $cmd == "apt-get" ]]; then
			local ports="${v2ray_dynamicPort_start}:${v2ray_dynamicPort_end}"
			iptables -D INPUT -p tcp --match multiport --dports $ports -j ACCEPT
			iptables -D INPUT -p udp --match multiport --dports $ports -j ACCEPT
			ip6tables -D INPUT -p tcp --match multiport --dports $ports -j ACCEPT
			ip6tables -D INPUT -p udp --match multiport --dports $ports -j ACCEPT
			# else
			# 	local ports="${v2ray_dynamicPort_start}-${v2ray_dynamicPort_end}"
			# 	firewall-cmd --permanent --zone=public --remove-port=$ports/tcp
			# 	firewall-cmd --permanent --zone=public --remove-port=$ports/udp
			# fi
		fi
		iptables-save >/etc/iptables.rules.v4
		ip6tables-save >/etc/iptables.rules.v6
		# else
		# 	service iptables save >/dev/null 2>&1
		# 	service ip6tables save >/dev/null 2>&1
	fi

}

config() {
	cp -f /etc/v2ray/kikunae77/v2ray/config/backup.conf $backup
	cp -f /etc/v2ray/kikunae77/v2ray/v2ray.sh $_v2ray_sh
	chmod +x $_v2ray_sh

	v2ray_id=$uuid
	alterId=233
	ban_bt=true
	if [[ $v2ray_transport -ge 18 ]]; then
		v2ray_dynamicPort_start=${v2ray_dynamic_port_start_input}
		v2ray_dynamicPort_end=${v2ray_dynamic_port_end_input}
	fi
	_load config.sh

	if [[ $cmd == "apt-get" ]]; then
		cat >/etc/network/if-pre-up.d/iptables <<-EOF
			#!/bin/sh
			/sbin/iptables-restore < /etc/iptables.rules.v4
			/sbin/ip6tables-restore < /etc/iptables.rules.v6
		EOF
		chmod +x /etc/network/if-pre-up.d/iptables
		# else
		# 	[ $(pgrep "firewall") ] && systemctl stop firewalld
		# 	systemctl mask firewalld
		# 	systemctl disable firewalld
		# 	systemctl enable iptables
		# 	systemctl enable ip6tables
		# 	systemctl start iptables
		# 	systemctl start ip6tables
	fi

	[[ $shadowsocks ]] && open_port $ssport
	if [[ $v2ray_transport == [45] ]]; then
		open_port "80"
		open_port "443"
		open_port $v2ray_port
	elif [[ $v2ray_transport -ge 18 ]]; then
		open_port $v2ray_port
		open_port "multiport"
	else
		open_port $v2ray_port
	fi
	# systemctl restart v2ray
	do_service restart v2ray
	backup_config

}

backup_config() {
	sed -i "18s/=1/=$v2ray_transport/; 21s/=2333/=$v2ray_port/; 24s/=$old_id/=$uuid/" $backup
	if [[ $v2ray_transport -ge 18 ]]; then
		sed -i "30s/=10000/=$v2ray_dynamic_port_start_input/; 33s/=20000/=$v2ray_dynamic_port_end_input/" $backup
	fi
	if [[ $shadowsocks ]]; then
		sed -i "42s/=/=true/; 45s/=6666/=$ssport/; 48s/=233blog.com/=$sspass/; 51s/=chacha20-ietf/=$ssciphers/" $backup
	fi
	[[ $v2ray_transport == [45] ]] && sed -i "36s/=233blog.com/=$domain/" $backup
	[[ $caddy ]] && sed -i "39s/=/=true/" $backup
	[[ $ban_ad ]] && sed -i "54s/=/=true/" $backup
	if [[ $is_path ]]; then
		sed -i "57s/=/=true/; 60s/=233blog/=$path/" $backup
		sed -i "63s#=https://liyafly.com#=$proxy_site#" $backup
	fi
}

get_ip() {
	ip=$(curl -s https://ipinfo.io/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.ip.sb/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.ipify.org)
	[[ -z $ip ]] && ip=$(curl -s https://ip.seeip.org)
	[[ -z $ip ]] && ip=$(curl -s https://ifconfig.co/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
	[[ -z $ip ]] && ip=$(curl -s icanhazip.com)
	[[ -z $ip ]] && ip=$(curl -s myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
	[[ -z $ip ]] && echo -e "\n$red 스크립트가 좀 구려요!$none\n" && exit
}

error() {

	echo -e "\n$red 입력 오류！$none\n"

}

pause() {

	read -rsp "$(echo -e "$green Enter 키$none를 누르면 설치를 진행합니다.... 또는 $red Ctrl + C $none를 눌러 취소하세요.")" -d $'\n'
	echo
}
do_service() {
	if [[ $systemd ]]; then
		systemctl $1 $2
	else
		service $2 $1
	fi
}
show_config_info() {
	clear
	_load v2ray-info.sh
	_v2_args
	_v2_info
	_load ss-info.sh

}

install() {
	if [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f $backup && -d /etc/v2ray/kikunae77/v2ray ]]; then
		echo
		echo " 이미 V2Ray가 설치되어 있습니다. 다시 설치할 필요가 없습니다."
		echo
		echo -e " ${cyan}v2ray${none}를 입력하여 $yellow V2Ray${none}를 관리할 수 있습니다."
		echo
		exit 1
	elif [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f /etc/v2ray/szkorean_v2ray_backup.txt && -d /etc/v2ray/kikunae77/v2ray ]]; then
		echo
		echo "  계속 설치하시려면 우선 구버전을 삭제하시기 바랍니다."
		echo
		echo -e " ${cyan}v2ray uninstall${none}을 입력하여 $yellow삭제${none}할 수 있습니다."
		echo
		exit 1
	fi
	v2ray_config
	blocked_hosts
	shadowsocks_config
	install_info
	# [[ $caddy ]] && domain_check
	install_v2ray
	if [[ $caddy || $v2ray_port == "80" ]]; then
		if [[ $cmd == "yum" ]]; then
			[[ $(pgrep "httpd") ]] && systemctl stop httpd
			[[ $(command -v httpd) ]] && yum remove httpd -y
		else
			[[ $(pgrep "apache2") ]] && service apache2 stop
			[[ $(command -v apache2) ]] && apt-get remove apache2* -y
		fi
	fi
	[[ $caddy ]] && install_caddy

	## bbr
	_load bbr.sh
	_try_enable_bbr

	get_ip
	config
	show_config_info
}
uninstall() {

	if [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f $backup && -d /etc/v2ray/kikunae77/v2ray ]]; then
		. $backup
		if [[ $mark ]]; then
			_load uninstall.sh
		else
			echo
			echo -e " $yellow ${cyan}v2ray uninstall${none}을 입력하여 $yellow삭제${none}할 수 있습니다."
			echo
		fi

	elif [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f /etc/v2ray/szkorean_v2ray_backup.txt && -d /etc/v2ray/kikunae77/v2ray ]]; then
		echo
		echo -e " ${cyan}v2ray uninstall${none}을 입력하여 $yellow삭제${none}할 수 있습니다."
		echo
	else
		echo -e "
		$red V2Ray가 설치되어 있지 않습니다...$none
		
		.참고..233v2.com에서 제공하는 V2Ray 스크립트를 사용하세요.
		" && exit 1
	fi

}

args=$1
_gitbranch=$2
[ -z $1 ] && args="online"
case $args in
online)
	#hello world
	[[ -z $_gitbranch ]] && _gitbranch="master"
	;;
local)
	local_install=true
	;;
*)
	echo
	echo -e " 입력한 인수 <$red $args $none>는 지원하지 않습니다."
	echo
	echo -e " 이 스크립트는 $green local / online $none 두가지 인수를 지원합니다."
	echo
	echo -e " $yellow local $none은 시스템 내 파일로 설치가 진행되고"
	echo
	echo -e " $yellow online $none은 온라인에서 파일을 받아 설치합니다. (기본값)"
	echo
	exit 1
	;;
esac

clear
while :; do
	echo
	echo "........... V2Ray 설치 및 관리 스크립트 by 233v2.com .........."
	echo
	echo "도움말 (중국어): https://233v2.com/post/1/"
	echo
	echo "설치 강좌 (중국어): https://233v2.com/post/2/"
	echo
	echo " 1. 설치"
	echo
	echo " 2. 삭제"
	echo
	if [[ $local_install ]]; then
		echo -e "$yellow 참고.. 로컬 설치를 진행합니다. ..$none"
		echo
	fi
	read -p "$(echo -e "선택하세요. [${magenta}1-2$none]:")" choose
	case $choose in
	1)
		install
		break
		;;
	2)
		uninstall
		break
		;;
	*)
		error
		;;
	esac
done
