#!/bin/bash

red='\e[91m'
green='\e[92m'
yellow='\e[93m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'

# Root
[[ $(id -u) != 0 ]] && echo -e "  ${red}root ${none}계정으로 스크립트를 실행해 주세요. ${yellow}~(^_^) ${none}" && exit 1

_version="v3.15"

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

if [[ $(command -v yum) ]]; then

	cmd="yum"

fi

backup="/etc/v2ray/233blog_v2ray_backup.conf"

if [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f $backup && -d /etc/v2ray/233boy/v2ray ]]; then

	. $backup

elif [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f /etc/v2ray/233blog_v2ray_backup.txt && -d /etc/v2ray/233boy/v2ray ]]; then

	. /etc/v2ray/233boy/v2ray/tools/v1xx_to_v3xx.sh

else
	echo -e " ${red}에러가 발생했습니다...V2Ray${none}를 다시 설치해 주세요${yellow}~(^_^) ${none}" && exit 1
fi

if [[ $mark != "v3" ]]; then
	. /etc/v2ray/233boy/v2ray/tools/v3.sh
fi
if [[ $v2ray_transport -ge 18 ]]; then
	dynamicPort=true
	port_range="${v2ray_dynamicPort_start}-${v2ray_dynamicPort_end}"
fi
if [[ $path_status ]]; then
	is_path=true
fi

uuid=$(cat /proc/sys/kernel/random/uuid)
old_id="e55c8d17-2cf3-b21a-bcf1-eeacb011ed79"
v2ray_server_config="/etc/v2ray/config.json"
v2ray_client_config="/etc/v2ray/233blog_v2ray_config.json"
v2ray_pid=$(pgrep -f /usr/bin/v2ray/v2ray)
caddy_pid=$(pgrep -f /usr/local/bin/caddy)
_v2ray_sh="/usr/local/sbin/v2ray"
v2ray_ver="$(/usr/bin/v2ray/v2ray -version | head -n 1 | cut -d " " -f2)"
. /etc/v2ray/233boy/v2ray/src/init.sh
systemd=true
# _test=true

if [[ $v2ray_ver != v* ]]; then
	v2ray_ver="v$v2ray_ver"
fi
if [[ ! -f $_v2ray_sh ]]; then
	mv -f /usr/local/bin/v2ray $_v2ray_sh
	chmod +x $_v2ray_sh
	echo -e "\n $yellow 경고: v2ray 명령어를 찾지 못하는 문제를 방지하기 위해 SSH에 다시 로그인 해주세요.$none  \n" && exit 1
fi

if [ $v2ray_pid ]; then
	v2ray_status="$green실행중行$none"
else
	v2ray_status="$red미실행중$none"
fi
if [[ $v2ray_transport == [45] && $caddy ]] && [[ $caddy_pid ]]; then
	caddy_run_status="$green실행중$none"
else
	caddy_run_status="$red미실행중$none"
fi

_load transport.sh
ciphers=(
	aes-128-cfb
	aes-256-cfb
	chacha20
	chacha20-ietf
	aes-128-gcm
	aes-256-gcm
	chacha20-ietf-poly1305
)

get_transport_args() {
	_load v2ray-info.sh
	_v2_args
}
create_vmess_URL_config() {

	[[ -z $net ]] && get_transport_args

	if [[ $v2ray_transport == [45] ]]; then
		cat >/etc/v2ray/vmess_qr.json <<-EOF
		{
			"v": "2",
			"ps": "233v2.com_${domain}",
			"add": "${domain}",
			"port": "443",
			"id": "${v2ray_id}",
			"aid": "${alterId}",
			"net": "${net}",
			"type": "none",
			"host": "${domain}",
			"path": "$_path",
			"tls": "tls"
		}
		EOF
	else
		[[ -z $ip ]] && get_ip
		cat >/etc/v2ray/vmess_qr.json <<-EOF
		{
			"v": "2",
			"ps": "233v2.com_${ip}",
			"add": "${ip}",
			"port": "${v2ray_port}",
			"id": "${v2ray_id}",
			"aid": "${alterId}",
			"net": "${net}",
			"type": "${header}",
			"host": "${host}",
			"path": "",
			"tls": ""
		}
		EOF
	fi
}
view_v2ray_config_info() {

	_load v2ray-info.sh
	_v2_args
	_v2_info
}
get_shadowsocks_config() {
	if [[ $shadowsocks ]]; then

		while :; do
			echo
			echo -e "$yellow 1. $none Shadowsocks 설정 정보 보기"
			echo
			echo -e "$yellow 2. $none QR코드 링크 생성"
			echo
			read -p "$(echo -e "선택해주세요. [${magenta}1-2$none]:")" _opt
			if [[ -z $_opt ]]; then
				error
			else
				case $_opt in
				1)
					view_shadowsocks_config_info
					break
					;;
				2)
					get_shadowsocks_config_qr_link
					break
					;;
				*)
					error
					;;
				esac
			fi

		done
	else
		shadowsocks_config
	fi
}
view_shadowsocks_config_info() {
	if [[ $shadowsocks ]]; then
		_load ss-info.sh
	else
		shadowsocks_config
	fi
}
get_shadowsocks_config_qr_link() {
	if [[ $shadowsocks ]]; then
		get_ip
		_load qr.sh
		_ss_qr
	else
		shadowsocks_config
	fi

}

get_shadowsocks_config_qr_ask() {
	echo
	while :; do
		echo -e "$yellow Shadowsocks 설정 정보 $none QR코드 링크를 생성하시겠습니까? [${magenta}Y/N$none]"
		read -p "$(echo -e "기본값 [${magenta}N$none]:")" y_n
		[ -z $y_n ] && y_n="n"
		if [[ $y_n == [Yy] ]]; then
			get_shadowsocks_config_qr_link
			break
		elif [[ $y_n == [Nn] ]]; then
			break
		else
			error
		fi
	done

}
change_shadowsocks_config() {
	if [[ $shadowsocks ]]; then

		while :; do
			echo
			echo -e "$yellow 1. $none Shadowsocks 포트 수정"
			echo
			echo -e "$yellow 2. $none Shadowsocks 비밀번호 수정"
			echo
			echo -e "$yellow 3. $none Shadowsocks 암호화 프로토콜 수정"
			echo
			echo -e "$yellow 4. $none Shadowsocks 중단"
			echo
			read -p "$(echo -e "선택해주세요 [${magenta}1-4$none]:")" _opt
			if [[ -z $_opt ]]; then
				error
			else
				case $_opt in
				1)
					change_shadowsocks_port
					break
					;;
				2)
					change_shadowsocks_password
					break
					;;
				3)
					change_shadowsocks_ciphers
					break
					;;
				4)
					disable_shadowsocks
					break
					;;
				*)
					error
					;;
				esac
			fi

		done
	else

		shadowsocks_config
	fi
}
shadowsocks_config() {
	echo
	echo
	echo -e " $red Shadowsocks를 설정하지 않으셨습니다... 필요하면 지금 설정할 수도 있습니다. ^_^"
	echo
	echo

	while :; do
		echo -e "${yellow}Shadowsocks${none}를 설치하시겠습니까? [${magenta}Y/N$none]"
		read -p "$(echo -e "(기본값 [${cyan}N$none]):") " install_shadowsocks
		[[ -z "$install_shadowsocks" ]] && install_shadowsocks="n"
		if [[ "$install_shadowsocks" == [Yy] ]]; then
			echo
			shadowsocks=true
			shadowsocks_port_config
			shadowsocks_password_config
			shadowsocks_ciphers_config
			pause
			open_port $new_ssport
			backup_config +ss
			ssport=$new_ssport
			sspass=$new_sspass
			ssciphers=$new_ssciphers
			config
			clear
			view_shadowsocks_config_info
			# get_shadowsocks_config_qr_ask
			break
		elif [[ "$install_shadowsocks" == [Nn] ]]; then
			echo
			echo -e " $green Shadowsocks 설치를 중단하셨습니다....$none"
			echo
			break
		else
			error
		fi

	done
}
shadowsocks_port_config() {
	local random=$(shuf -i20001-65535 -n1)
	while :; do
		echo -e " "$yellow"Shadowsocks"$none" 포트번호를 입력해주세요. ["$magenta"1-65535"$none"]"$yellow"V2ray"$none" 포트번호와 동일한 번호는 사용할 수 없습니다."
		read -p "$(echo -e "(기본 포트: ${cyan}${random}$none):") " new_ssport
		[ -z "$new_ssport" ] && new_ssport=$random
		case $new_ssport in
		$v2ray_port)
			echo
			echo -e " $cyan V2Ray 포트 $none와 같으면 안됩니다...."
			echo
			echo -e " 기존 V2Ray 포트：${cyan}$v2ray_port${none}"
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $v2ray_transport == [45] ]]; then
				local tls=ture
			fi
			if [[ $tls && $new_ssport == "80" ]] || [[ $tls && $new_ssport == "443" ]]; then
				echo
				echo -e " "$green"WebSocket + TLS $none및$green HTTP/2"$none" 전송 프로토콜이 사용중인 포트입니다."
				echo
				echo -e " "$magenta"80"$none" 및 "$magenta"443"$none" 포트는 선택 불가능합니다."
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start == $new_ssport || $v2ray_dynamicPort_end == $new_ssport ]]; then
				echo
				echo -e " 죄송합니다. 이 포트와 V2Ray 동적포트가 충돌합니다. 기존 V2Ray 동적포트 범위：${cyan}$port_range${none}"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start -lt $new_ssport && $new_ssport -le $v2ray_dynamicPort_end ]]; then
				echo
				echo -e " 죄송합니다. 이 포트와 V2Ray 동적포트가 충돌합니다. 기존 V2Ray 동적포트 범위：${cyan}$port_range${none}"
				error
			elif [[ $socks && $new_ssport == $socks_port ]]; then
				echo
				echo -e " 죄송합니다. 이 포트와 Socks 포트가 충돌합니다. 기존 Socks 포트: ${cyan}$socks_port$none"
				error
			elif [[ $mtproto && $new_ssport == $mtproto_port ]]; then
				echo
				echo -e " 죄송합니다. 이 포트와 MTProto 포트가 충돌합니다. 기존 MTProto 포트: ${cyan}$mtproto_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow Shadowsocks 포트 = $cyan$new_ssport$none"
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

shadowsocks_password_config() {

	while :; do
		echo -e " "$yellow"Shadowsocks"$none" 비밀번호를 입력해 주세요."
		read -p "$(echo -e "(기본 비번: ${cyan}szkorean.net$none)"): " new_sspass
		[ -z "$new_sspass" ] && new_sspass="szkorean.net"
		case $new_sspass in
		*[/$]*)
			echo
			echo -e " $red / $none또는$red $ $none 특수기호는 비번에 포함시킬 수 없습니다...."
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow Shadowsocks 비밀번호 = $cyan$new_sspass$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac

	done

}

shadowsocks_ciphers_config() {

	while :; do
		echo -e " "$yellow"Shadowsocks"$none" 암호화 프로토콜을 선택하세요. [${magenta}1-7$none]"
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
			new_ssciphers=${ciphers[$ssciphers_opt - 1]}
			echo
			echo
			echo -e "$yellow Shadowsocks 암호화 프로토콜 = $cyan${new_ssciphers}$none"
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

change_shadowsocks_port() {
	echo
	while :; do
		echo -e " "$yellow"Shadowsocks"$none" 포트번호를 입력해주세요. ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(기존 포트번호: ${cyan}$ssport$none):") " new_ssport
		[ -z "$new_ssport" ] && error && continue
		case $new_ssport in
		$ssport)
			echo
			echo " 기존 번호랑 동일한 번호입니다... 수정해주세요."
			error
			;;
		$v2ray_port)
			echo
			echo -e " $cyan V2Ray 포트 번호$none와 같을 수 없습니다...."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $v2ray_transport == [45] ]]; then
				local tls=ture
			fi
			if [[ $tls && $new_ssport == "80" ]] || [[ $tls && $new_ssport == "443" ]]; then
				echo
				echo -e " "$green"WebSocket + TLS $none및$green HTTP/2"$none" 전송 프로토콜이 사용중인 포트입니다."
				echo
				echo -e " "$magenta"80"$none" 및 "$magenta"443"$none" 포트는 선택 불가능합니다."
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start == $new_ssport || $v2ray_dynamicPort_end == $new_ssport ]]; then
				echo
				echo -e " 죄송합니다. 이 포트와 V2Ray 동적포트가 충돌합니다. 기존 V2Ray 동적포트 범위：${cyan}$port_range${none}"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start -lt $new_ssport && $new_ssport -le $v2ray_dynamicPort_end ]]; then
				echo
				echo -e " 죄송합니다. 이 포트와 V2Ray 동적포트가 충돌합니다. 기존 V2Ray 동적포트 범위：${cyan}$port_range${none}"
				error
			elif [[ $socks && $new_ssport == $socks_port ]]; then
				echo
				echo -e " 죄송합니다. 이 포트와 Socks 포트가 충돌합니다. 기존 Socks 포트: ${cyan}$socks_port$none"
				error
			elif [[ $mtproto && $new_ssport == $mtproto_port ]]; then
				echo
				echo -e " 죄송합니다. 이 포트와 MTProto 포트가 충돌합니다. 기존 MTProto 포트: ${cyan}$mtproto_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow Shadowsocks 포트 = $cyan$new_ssport$none"
				echo "----------------------------------------------------------------"
				echo
				pause
				backup_config ssport
				del_port $ssport
				open_port $new_ssport
				ssport=$new_ssport
				config
				clear
				view_shadowsocks_config_info
				# get_shadowsocks_config_qr_ask
				break
			fi
			;;
		*)
			error
			;;
		esac

	done
}
change_shadowsocks_password() {
	echo
	while :; do
		echo -e " "$yellow"Shadowsocks"$none" 비밀번호를 입력해 주세요."
		read -p "$(echo -e "(기존 비밀번호：${cyan}$sspass$none)"): " new_sspass
		[ -z "$new_sspass" ] && error && continue
		case $new_sspass in
		$sspass)
			echo
			echo " 기존 비밀번호와 동일합니다. 다르게 설정해 주세요."
			error
			;;
		*[/$]*)
			echo
			echo -e " $red / $none또는$red $ $none 특수기호는 비번에 포함시킬 수 없습니다...."
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow Shadowsocks 비밀번호 = $cyan$new_sspass$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config sspass
			sspass=$new_sspass
			config
			clear
			view_shadowsocks_config_info
			# get_shadowsocks_config_qr_ask
			break
			;;
		esac

	done

}

change_shadowsocks_ciphers() {
	echo
	while :; do
		echo -e " "$yellow"Shadowsocks"$none" 암호화 프로토콜을 선택하세요. [${magenta}1-${#ciphers[*]}$none]"
		for ((i = 1; i <= ${#ciphers[*]}; i++)); do
			ciphers_show="${ciphers[$i - 1]}"
			echo
			echo -e "$yellow $i. $none${ciphers_show}"
		done
		echo
		read -p "$(echo -e "(기존 암호화 프로토콜: ${cyan}${ssciphers}$none)"):" ssciphers_opt
		[ -z "$ssciphers_opt" ] && error && continue
		case $ssciphers_opt in
		[1-7])
			new_ssciphers=${ciphers[$ssciphers_opt - 1]}
			if [[ $new_ssciphers == $ssciphers ]]; then
				echo
				echo " 기존 암호화 프로토콜과 동일합니다. 다르게 선택해 주세요."
				error && continue
			fi
			echo
			echo
			echo -e "$yellow Shadowsocks 암호화 프로토콜 = $cyan${new_ssciphers}$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config ssciphers
			ssciphers=$new_ssciphers
			config
			clear
			view_shadowsocks_config_info
			# get_shadowsocks_config_qr_ask
			break
			;;
		*)
			error
			;;
		esac

	done

}
disable_shadowsocks() {
	echo

	while :; do
		echo -e " ${yellow}Shadowsocks${none}를 중단 하시겠습니까?[${magenta}Y/N$none]"
		read -p "$(echo -e "(기본값 [${cyan}N$none]):") " y_n
		[[ -z "$y_n" ]] && y_n="n"
		if [[ "$y_n" == [Yy] ]]; then
			echo
			echo
			echo -e "$yellow Shadowsocks 중단 = $cyan예$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config -ss
			del_port $ssport
			shadowsocks=''
			config
			# clear
			echo
			echo
			echo
			echo -e "$green Shadowsocks가 이미 중단되었습니다... 나중에 Shadowsocks를 다시 시작하실 수 있습니다.$none"
			echo
			break
		elif [[ "$y_n" == [Nn] ]]; then
			echo
			echo -e " $green Shadowsocks 중단이 취소되었습니다....$none"
			echo
			break
		else
			error
		fi

	done
}
change_v2ray_config() {
	local _menu=(
		" V2Ray 포트 수정"
		" V2Ray 전송 프로토콜 수정"
		" V2Ray 동적포트 수정 (가능한 경우)"
		" 사용자 ID 수정 ( UUID )"
		" TLS 도메인 수정 (가능한 경우)"
		" Path(경로) 수정 (가능한 경우)"
		" Proxy (사이트주소 위장) 수정 (가능한 경우)"
		" Proxy 및 Path 중단 (가능한 경우)"
		" 광고 차단 시작/중단"
	)
	while :; do
		for ((i = 1; i <= ${#_menu[*]}; i++)); do
			if [[ "$i" -le 9 ]]; then
				echo
				echo -e "$yellow  $i. $none${_menu[$i - 1]}"
			else
				echo
				echo -e "$yellow $i. $none${_menu[$i - 1]}"
			fi
		done
		echo
		read -p "$(echo -e "선택하세요 [${magenta}1-${#_menu[*]}$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				change_v2ray_port
				break
				;;
			2)
				change_v2ray_transport
				break
				;;
			3)
				change_v2ray_dynamicport
				break
				;;
			4)
				change_v2ray_id
				break
				;;
			5)
				change_domain
				break
				;;
			6)
				change_path_config
				break
				;;
			7)
				change_proxy_site_config
				break
				;;
			8)
				disable_path
				break
				;;
			9)
				blocked_hosts
				break
				;;
			[aA][Ii][aA][Ii] | [Dd][Dd])
				custom_uuid
				break
				;;
			[Dd] | [Aa][Ii] | 233 | 233[Bb][Ll][Oo][Gg] | 233[Bb][Ll][Oo][Gg].[Cc][Oo][Mm] | 233[Bb][Oo][Yy] | [Aa][Ll][Tt][Ee][Rr][Ii][Dd])
				change_v2ray_alterId
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
change_v2ray_port() {
	if [[ $v2ray_transport == 4 ]]; then
		echo
		echo -e " 기존에$yellow WebSocket + TLS $none전송 프로토콜을 사용 중이므로, V2Ray 포트 변경은 의미가 없습니다."
		echo
		echo " 만약 다른 포토를 사용하고 싶으시면, 우선 V2Ray 전송 프로토콜을 먼저 변경하시고 V2Ray 포트를 변경하세요."
		echo
		change_v2ray_transport_ask
	elif [[ $v2ray_transport == 5 ]]; then
		echo
		echo -e " 기존에$yellow HTTP/2 $none전송 프로토콜을 사용 중이므로, V2Ray 포트 변경은 의미가 없습니다."
		echo
		echo " 만약 다른 포토를 사용하고 싶으시면, 우선 V2Ray 전송 프로토콜을 먼저 변경하시고 V2Ray 포트를 변경하세요."
		echo
		change_v2ray_transport_ask
	else
		echo
		while :; do
			echo -e " "$yellow"V2Ray"$none" 포트번호 입력 ["$magenta"1-65535"$none"]"
			read -p "$(echo -e "(기존 포트번호: ${cyan}${v2ray_port}$none):")" v2ray_port_opt
			[[ -z $v2ray_port_opt ]] && error && continue
			case $v2ray_port_opt in
			$v2ray_port)
				echo
				echo " 기존 포트와 동일합니다... 다른 포트로 수정해 주세요."
				error
				;;
			[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
				if [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start == $v2ray_port_opt || $v2ray_dynamicPort_end == $v2ray_port_opt ]]; then
					echo
					echo -e " 죄송합니다. 이 포트와 V2Ray 동적포트가 충돌합니다. 기존 V2Ray 동적포트 범위：${cyan}$port_range${none}"
					error
				elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start -lt $v2ray_port_opt && $v2ray_port_opt -le $v2ray_dynamicPort_end ]]; then
					echo
					echo -e " 죄송합니다. 이 포트와 V2Ray 동적포트가 충돌합니다. 기존 V2Ray 동적포트 범위：${cyan}$port_range${none}"
					error
				elif [[ $shadowsocks && $v2ray_port_opt == $ssport ]]; then
					echo
					echo -e " 죄송합니다. 이 포트와 Shadowsocks 포트가 충돌합니다...기존 Shadowsocks 포트: ${cyan}$ssport$none"
					error
				elif [[ $socks && $v2ray_port_opt == $socks_port ]]; then
					echo
					echo -e " 죄송합니다. 이 포트와 Socks 포트가 충돌합니다. 기존 Socks 포트: ${cyan}$socks_port$none"
					error
				elif [[ $mtproto && $v2ray_port_opt == $mtproto_port ]]; then
					echo
					echo -e " 죄송합니다. 이 포트와 MTProto 포트가 충돌합니다. 기존 MTProto 포트: ${cyan}$mtproto_port$none"
					error
				else
					echo
					echo
					echo -e "$yellow V2Ray 포트 = $cyan$v2ray_port_opt$none"
					echo "----------------------------------------------------------------"
					echo
					pause
					backup_config v2ray_port
					del_port $v2ray_port
					open_port $v2ray_port_opt
					v2ray_port=$v2ray_port_opt
					config
					clear
					view_v2ray_config_info
					# download_v2ray_config_ask
					break
				fi
				;;
			*)
				error
				;;
			esac

		done
	fi

}
download_v2ray_config_ask() {
	echo
	while :; do
		echo -e " V2Ray 설정 다운로드 / 설정정보 링크 생성 / QR코드 링크 생성을 하시겠습니까? [${magenta}Y/N$none]"
		read -p "$(echo -e "기본값  [${cyan}N$none]:")" y_n
		[ -z $y_n ] && y_n="n"
		if [[ $y_n == [Yy] ]]; then
			download_v2ray_config
			break
		elif [[ $y_n == [Nn] ]]; then
			break
		else
			error
		fi
	done

}
change_v2ray_transport_ask() {
	echo
	while :; do
		echo -e "$yellow V2Ray $none 전송 프로토콜을 수정하시겠습니까? [${magenta}Y/N$none]"
		read -p "$(echo -e "기본값  [${cyan}N$none]:")" y_n
		[ -z $y_n ] && break
		if [[ $y_n == [Yy] ]]; then
			change_v2ray_transport
			break
		elif [[ $y_n == [Nn] ]]; then
			break
		else
			error
		fi
	done
}
change_v2ray_transport() {
	echo
	while :; do
		echo -e " "$yellow"V2Ray"$none" 전송 프로토콜 선택 [${magenta}1-${#transport[*]}$none]"
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
		read -p "$(echo -e "(기존 전송 프로토콜: ${cyan}${transport[$v2ray_transport - 1]}$none)"):" v2ray_transport_opt
		if [ -z "$v2ray_transport_opt" ]; then
			error
		else
			case $v2ray_transport_opt in
			$v2ray_transport)
				echo
				echo " 기존 전송 프로토콜과 동일합니다...다른 프로토콜로 수정해 주세요."
				error
				;;
			4 | 5)
				if [[ $v2ray_port == "80" || $v2ray_port == "443" ]]; then
					echo
					echo -e " 죄송합니다...${cyan} ${transport[$v2ray_transport_opt - 1]} $none전송 프로토콜을 사용하시려면 ${red}V2Ray 포트는 80 또는 443을 사용할 수 없습니다...$none"
					echo
					echo -e " 기존 V2Ray 포트: ${cyan}$v2ray_port$none"
					error
				elif [[ $shadowsocks ]] && [[ $ssport == "80" || $ssport == "443" ]]; then
					echo
					echo -e " 죄송합니다...${cyan} ${transport[$v2ray_transport_opt - 1]} $none전송 프로토콜을 사용하시려면 ${red}Shadowsocks 포트는 80 또는 443을 사용할 수 없습니다...$none"
					echo
					echo -e " 기존 Shadowsocks 포트: ${cyan}$ssport$none"
					error
				elif [[ $socks ]] && [[ $socks_port == "80" || $socks_port == "443" ]]; then
					echo
					echo -e " 죄송합니다...${cyan} ${transport[$v2ray_transport_opt - 1]} $none전송 프로토콜을 사용하시려면 ${red}Socks 포트는 80 또는 443을 사용할 수 없습니다...$none"
					echo
					echo -e " 기존 Socks 포트: ${cyan}$socks_port$none"
					error
				elif [[ $mtproto ]] && [[ $mtproto_port == "80" || $mtproto_port == "443" ]]; then
					echo
					echo -e " 죄송합니다...${cyan} ${transport[$v2ray_transport_opt - 1]} $none전송 프로토콜을 사용하시려면 ${red}MTProto 포트는 80 또는 443을 사용할 수 없습니다...$none"
					echo
					echo -e " 기존 MTProto 포트: ${cyan}$mtproto_port$none"
					error
				else
					echo
					echo
					echo -e "$yellow V2Ray 전송 프로토콜 = $cyan${transport[$v2ray_transport_opt - 1]}$none"
					echo "----------------------------------------------------------------"
					echo
					break
				fi
				;;
			[1-9] | [1-2][0-9] | 3[0-2])
				echo
				echo
				echo -e "$yellow V2Ray 전송 프로토콜 = $cyan${transport[$v2ray_transport_opt - 1]}$none"
				echo "----------------------------------------------------------------"
				echo
				break
				;;
			*)
				error
				;;
			esac
		fi

	done
	pause

	if [[ $v2ray_transport_opt == [45] ]]; then
		tls_config
	elif [[ $v2ray_transport_opt -ge 18 ]]; then
		v2ray_dynamic_port_start
		v2ray_dynamic_port_end
		pause
		old_transport
		open_port "multiport"
		backup_config v2ray_transport v2ray_dynamicPort_start v2ray_dynamicPort_end
		port_range="${v2ray_dynamic_port_start_input}-${v2ray_dynamic_port_end_input}"
		v2ray_transport=$v2ray_transport_opt
		config
		clear
		view_v2ray_config_info
		# download_v2ray_config_ask
	else
		old_transport
		backup_config v2ray_transport
		v2ray_transport=$v2ray_transport_opt
		config
		clear
		view_v2ray_config_info
		# download_v2ray_config_ask
	fi

}
old_transport() {
	if [[ $v2ray_transport == [45] ]]; then
		del_port "80"
		del_port "443"
		if [[ $caddy && $caddy_pid ]]; then
			do_service stop caddy
			if [[ $systemd ]]; then
				systemctl disable caddy >/dev/null 2>&1
			else
				update-rc.d -f caddy remove >/dev/null 2>&1
			fi
		elif [[ $caddy ]]; then
			if [[ $systemd ]]; then
				systemctl disable caddy >/dev/null 2>&1
			else
				update-rc.d -f caddy remove >/dev/null 2>&1
			fi
		fi
		if [[ $is_path ]]; then
			backup_config -path
		fi
	elif [[ $v2ray_transport -ge 18 ]]; then
		del_port "multiport"
	fi
}

tls_config() {
	while :; do
		echo
		echo
		echo
		echo -e " $magenta정확한 도메인명$none을 입력해 주세요."
		read -p "(예：szkorean.net): " new_domain
		[ -z "$new_domain" ] && error && continue
		echo
		echo
		echo -e "$yellow 도메인명 = $cyan$new_domain$none"
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

		read -p "$(echo -e "(제대로 해석되었습니까?: [${magenta}Y$none]):") " record
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

	if [[ $caddy ]]; then
		path_config_ask
		pause
		# domain_check
		backup_config v2ray_transport domain
		if [[ $new_path ]]; then
			backup_config +path
			path=$new_path
			proxy_site=$new_proxy_site
			is_path=true
		fi

		if [[ $v2ray_transport -ge 18 ]]; then
			del_port "multiport"
		fi
		domain=$new_domain

		open_port "80"
		open_port "443"
		if [[ $systemd ]]; then
			systemctl enable caddy >/dev/null 2>&1
		else
			update-rc.d -f caddy defaults >/dev/null 2>&1
		fi
		v2ray_transport=$v2ray_transport_opt
		caddy_config
		config
		clear
		view_v2ray_config_info
		# download_v2ray_config_ask
	else
		if [[ $v2ray_transport_opt == 5 ]]; then
			path_config_ask
			pause
			domain_check
			backup_config v2ray_transport domain caddy
			if [[ $new_path ]]; then
				backup_config +path
				path=$new_path
				proxy_site=$new_proxy_site
				is_path=true
			fi
			if [[ $v2ray_transport -ge 18 ]]; then
				del_port "multiport"
			fi
			domain=$new_domain
			install_caddy
			open_port "80"
			open_port "443"
			v2ray_transport=$v2ray_transport_opt
			caddy_config
			config
			caddy=true
			clear
			view_v2ray_config_info
			# download_v2ray_config_ask
		else
			auto_tls_config
		fi
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
				echo
				echo
				echo -e "$yellow TLS 자동 설정 = $cyan켬$none"
				echo "----------------------------------------------------------------"
				echo
				path_config_ask
				pause
				domain_check
				backup_config v2ray_transport domain caddy
				if [[ $new_path ]]; then
					backup_config +path
					path=$new_path
					proxy_site=$new_proxy_site
					is_path=true
				fi
				if [[ $v2ray_transport -ge 18 ]]; then
					del_port "multiport"
				fi
				domain=$new_domain
				install_caddy
				open_port "80"
				open_port "443"
				v2ray_transport=$v2ray_transport_opt
				caddy_config
				config
				caddy=true
				clear
				view_v2ray_config_info
				# download_v2ray_config_ask
				break
			elif [[ "$auto_install_caddy" == [Nn] ]]; then
				echo
				echo
				echo -e "$yellow TLS 자동 설정 = $cyan끔$none"
				echo "----------------------------------------------------------------"
				echo
				pause
				domain_check
				backup_config v2ray_transport domain
				if [[ $v2ray_transport -ge 18 ]]; then
					del_port "multiport"
				fi
				domain=$new_domain
				open_port "80"
				open_port "443"
				v2ray_transport=$v2ray_transport_opt
				config
				clear
				view_v2ray_config_info
				# download_v2ray_config_ask
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
		read -p "$(echo -e "(기본값: [${cyan}N$none]):")" path_ask
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
		echo -e "${magenta}사용할 경로$none를 입력해 주세요. 예) /szkorean인 경우 szkorean 으로 입력하면 됩니다."
		read -p "$(echo -e "(기본값: [${cyan}szkorean$none]):")" new_path
		[[ -z $new_path ]] && new_path="szkorean"

		case $new_path in
		*[/$]*)
			echo
			echo -e " 경로에$red / $none나$red $ $none 특수기호를 포함할 수 없습니다...."
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow 경로 = ${cyan}/${new_path}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done
	proxy_site_config
}
proxy_site_config() {
	echo
	while :; do
		echo -e " ${magenta}정확한$none ${cyan}사이트 주소$none를 입력하여 ${cyan}사이트를 위장$none하세요. https://smartstore.naver.com/nyintl으로"
		echo -e "예를 들면... 만약 기존에 설정한 도메인이$green $domain $none인 경우, 위장할 사이트는 https://smartstore.naver.com/nyintl이 됩니다."
		echo -e "설정한 도메인으로 접속하면... 표시되는 내용은 https://smartstore.naver.com/nyintl의 내용이 표시됩니다."
		echo -e "Reverse Proxy로 이해하시면 됩니다.."
		echo -e "만약 위장에 성공하지 못하는 경우, v2ray config 으로 위장 사이트를 변경하세요."
		read -p "$(echo -e "(기본값: [${cyan}https://smartstore.naver.com/nyintl$none]):")" new_proxy_site
		[[ -z $new_proxy_site ]] && new_proxy_site="https://smartstore.naver.com/nyintl"

		case $new_proxy_site in
		*[#$]*)
			echo
			echo -e " 위장할 사이트 주소는$red # $none또는$red $ $none 특수기호를 포함할 수 없습니다.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow 위장할 사이트 주소 = ${cyan}${new_proxy_site}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done
}

install_caddy() {
	_load download-caddy.sh
	_download_caddy_file
	_install_caddy_service

}
caddy_config() {
	# local email=$(shuf -i1-10000000000 -n1)
	_load caddy-config.sh
	# systemctl restart caddy
	do_service restart caddy
}
v2ray_dynamic_port_start() {
	echo
	echo
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
			if [[ $shadowsocks && $v2ray_dynamic_port_start_input == $ssport ]]; then
				echo
				echo -e "죄송합니다. 이 포트는 Shadowsocks 포트와 충돌합니다...기존 Shadowsocks 포트: ${cyan}$ssport$none"
				error
			elif [[ $socks && $v2ray_dynamic_port_start_input == $socks_port ]]; then
				echo
				echo -e "죄송합니다. 이 포트는 Socks 포트와 충돌합니다...기존 Socks 포트: ${cyan}$socks_port$none"
				error
			elif [[ $mtproto && $v2ray_dynamic_port_start_input == $mtproto_port ]]; then
				echo
				echo -e "죄송합니다. 이 포트는 MTProto 포트와 충돌합니다...기존 MTProto 포트: ${cyan}$mtproto_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow V2Ray 동적포트 시작 포트 = $cyan$v2ray_dynamic_port_start_input$none"
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

	if [[ $v2ray_dynamic_port_start_input -lt $v2ray_port ]]; then
		lt_v2ray_port=true
	fi
	if [[ $shadowsocks ]] && [[ $v2ray_dynamic_port_start_input -lt $ssport ]]; then
		lt_ssport=true
	fi
	if [[ $socks ]] && [[ $v2ray_dynamic_port_start_input -lt $socks_port ]]; then
		lt_socks_port=true
	fi
	if [[ $mtproto ]] && [[ $v2ray_dynamic_port_start_input -lt $mtproto_port ]]; then
		lt_mtproto_port=true
	fi

}

v2ray_dynamic_port_end() {
	echo
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
				echo -e " 기존 V2Ray 포트: ${cyan}$v2ray_port$none"
				error
			elif [ $lt_ssport ] && [[ ${v2ray_dynamic_port_end_input} -ge $ssport ]]; then
				echo
				echo " V2Ray 동적포트 종료 포트는 Shadowsocks 포트를 포함할 수 없습니다..."
				echo
				echo -e " 기존 Shadowsocks 포트: ${cyan}$ssport$none"
				error
			elif [ $lt_socks_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $socks_port ]]; then
				echo
				echo " V2Ray 동적포트 종료 포트는 Socks 포트를 포함할 수 없습니다..."
				echo
				echo -e " 기존 Socks 포트: ${cyan}$socks_port$none"
				error
			elif [ $lt_mtproto_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $mtproto_port ]]; then
				echo
				echo " V2Ray 동적포트 종료 포트는 MTProto 포트를 포함할 수 없습니다..."
				echo
				echo -e " 기존 MTProto 포트: ${cyan}$mtproto_port$none"
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
change_v2ray_dynamicport() {
	if [[ $v2ray_transport -ge 18 ]]; then
		change_v2ray_dynamic_port_start
		change_v2ray_dynamic_port_end
		pause
		del_port "multiport"
		open_port "multiport"
		backup_config v2ray_dynamicPort_start v2ray_dynamicPort_end
		port_range="${v2ray_dynamic_port_start_input}-${v2ray_dynamic_port_end_input}"
		config
		# clear
		echo
		echo -e "$green 동적포트가 수정되었습니다... V2Ray 클라이언트 설정은 따로 변경하지 않아도 됩니다...$none"
		echo
	else
		echo
		echo -e "$red ...기존 전송 프로토콜이 동적 포트를 사용하지 못합니다...$none"
		echo
		while :; do
			echo -e "전송 프로토콜을 수정하시겠습니까? [${magenta}Y/N$none]"
			read -p "$(echo -e "기본값  [${cyan}N$none]:")" y_n
			if [[ -z $y_n ]]; then
				echo
				echo -e "$green 전송 프로토콜 수정이 취소되었습니다...$none"
				echo
				break
			else
				if [[ $y_n == [Yy] ]]; then
					change_v2ray_transport
					break
				elif [[ $y_n == [Nn] ]]; then
					echo
					echo -e "$green 전송 프로토콜 수정이 취소되었습니다...$none"
					echo
					break
				else
					error
				fi
			fi
		done

	fi
}
change_v2ray_dynamic_port_start() {
	echo
	echo
	while :; do
		echo -e " "$yellow"V2Ray 동적포트 시작 "$none"범위를 입력하세요. ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(기존 동적포트 시작 포트: ${cyan}$v2ray_dynamicPort_start$none):")" v2ray_dynamic_port_start_input
		[ -z $v2ray_dynamic_port_start_input ] && error && continue
		case $v2ray_dynamic_port_start_input in
		$v2ray_port)
			echo
			echo " V2Ray 포트와 같으면 안됩니다...."
			echo
			echo -e " 기존 V2Ray 포트：${cyan}$v2ray_port${none}"
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $shadowsocks && $v2ray_dynamic_port_start_input == $ssport ]]; then
				echo
				echo -e "죄송합니다. 이 포트는 Shadowsocks 포트와 충돌합니다... 기존 Shadowsocks 포트: ${cyan}$ssport$none"
				error
			elif [[ $socks && $v2ray_dynamic_port_start_input == $socks_port ]]; then
				echo
				echo -e "죄송합니다. 이 포트는 Socks 포트와 충돌합니다... 기존 Socks 포트: ${cyan}$socks_port$none"
				error
			elif [[ $mtproto && $v2ray_dynamic_port_start_input == $mtproto_port ]]; then
				echo
				echo -e "죄송합니다. 이 포트는 MTProto 포트와 충돌합니다... 기존 MTProto 포트: ${cyan}$mtproto_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow V2Ray 동적포트 시작 포트 = $cyan$v2ray_dynamic_port_start_input$none"
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

	if [[ $v2ray_dynamic_port_start_input -lt $v2ray_port ]]; then
		lt_v2ray_port=true
	fi
	if [[ $shadowsocks ]] && [[ $v2ray_dynamic_port_start_input -lt $ssport ]]; then
		lt_ssport=true
	fi
	if [[ $socks ]] && [[ $v2ray_dynamic_port_start_input -lt $socks_port ]]; then
		lt_socks_port=true
	fi
	if [[ $mtproto ]] && [[ $v2ray_dynamic_port_start_input -lt $mtproto_port ]]; then
		lt_mtproto_port=true
	fi
}

change_v2ray_dynamic_port_end() {
	echo
	while :; do
		echo -e " "$yellow"V2Ray 동적포트 종료 "$none"범위를 입력하세요. ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(기존 동적포트 종료 포트: ${cyan}$v2ray_dynamicPort_end$none):")" v2ray_dynamic_port_end_input
		[ -z $v2ray_dynamic_port_end_input ] && error && continue
		case $v2ray_dynamic_port_end_input in
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])

			if [[ $v2ray_dynamic_port_end_input -le $v2ray_dynamic_port_start_input ]]; then
				echo
				echo "  V2Ray 동적포트 시작 포트와 같거나 작을 수 없습니다."
				echo
				echo -e " 기존 V2Ray 동적포트 시작 포트：${cyan}$v2ray_dynamic_port_start_input${none}"
				error
			elif [ $lt_v2ray_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $v2ray_port ]]; then
				echo
				echo " V2Ray 동적포트 종료 범위는 V2Ray 포트를 포함할 수 없습니다..."
				echo
				echo -e " 기존 V2Ray 포트: ${cyan}$v2ray_port$none"
				error
			elif [ $lt_ssport ] && [[ ${v2ray_dynamic_port_end_input} -ge $ssport ]]; then
				echo
				echo " V2Ray 동적포트 종료 범위는 Shadowsocks 포트를 포함할 수 없습니다..."
				echo
				echo -e " 기존 Shadowsocks 포트: ${cyan}$ssport$none"
				error
			elif [ $lt_socks_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $socks_port ]]; then
				echo
				echo " V2Ray 동적포트 종료 범위는 Socks 포트를 포함할 수 없습니다..."
				echo
				echo -e " 기존 Socks 포트: ${cyan}$socks_port$none"
				error
			elif [ $lt_mtproto_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $mtproto_port ]]; then
				echo
				echo " V2Ray 동적포트 종료 범위는 MTProto 포트를 포함할 수 없습니다..."
				echo
				echo -e " 기존 MTProto 포트: ${cyan}$mtproto_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow V2Ray 동적포트 종료 포트 = $cyan$v2ray_dynamic_port_end_input$none"
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
change_v2ray_id() {
	echo
	while :; do
		echo -e "사용자ID를 변경하시겠습니까? [${magenta}Y/N$none]"
		read -p "$(echo -e "기본값  [${cyan}N$none]:")" y_n
		if [[ -z $y_n ]]; then
			echo
			echo -e "$green 사용자ID 변경이 취소되었습니다...$none"
			echo
			break
		else
			if [[ $y_n == [Yy] ]]; then
				echo
				echo
				echo -e "$yellow 사용자ID 변경 = $cyan확인됨$none"
				echo "----------------------------------------------------------------"
				echo
				pause
				backup_config uuid
				v2ray_id=$uuid
				config
				clear
				view_v2ray_config_info
				# download_v2ray_config_ask
				break
			elif [[ $y_n == [Nn] ]]; then
				echo
				echo -e "$green 사용자ID 변경이 취소되었습니다...$none"
				echo
				break
			else
				error
			fi
		fi
	done
}
change_domain() {
	if [[ $v2ray_transport == [45] ]] && [[ $caddy ]]; then
		while :; do
			echo
			echo -e " $magenta정확한 도메인명$none을 입력해 주세요."
			read -p "$(echo -e "(기존 도메인명: ${cyan}$domain$none):") " new_domain
			[ -z "$new_domain" ] && error && continue
			if [[ $new_domain == $domain ]]; then
				echo
				echo -e " 기존 도메인명과 동일합니다...다르게 수정해 주세요."
				echo
				error && continue
			fi
			echo
			echo
			echo -e "$yellow 새 도메인명 = $cyan$new_domain$none"
			echo "----------------------------------------------------------------"
			break
		done
		get_ip
		echo
		echo
		echo -e "$magenta$new_domain$none $yellow이 해석된 IP: $cyan$ip$none"
		echo
		echo -e "$magenta$new_domain$none $yellow이 해석된 IP: $cyan$ip$none"
		echo
		echo -e "$magenta$new_domain$none $yellow이 해석된 IP: $cyan$ip$none"
		echo "----------------------------------------------------------------"
		echo

		while :; do

			read -p "$(echo -e "(제대로 해석되었습니까?: [${magenta}Y$none]):") " record
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
					pause
					# domain_check
					backup_config domain
					domain=$new_domain
					caddy_config
					config
					clear
					view_v2ray_config_info
					# download_v2ray_config_ask
					break
				else
					error
				fi
			fi

		done
	else
		echo
		echo -e "$red 죄송합니다...수정이 불가능합니다...$none"
		echo
		echo -e " 참고.. TLS 도메인명 수정은 ${yellow}WebSocket + TLS$none 또는 ${yellow}HTTP/2$none 전송 프로토콜을 사용하고$yellow TLS 자동설정 = 켬$none인 경우에만 가능합니다."
		echo
		echo -e " 기존 전송 프로토콜: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
		if [[ $caddy ]]; then
			echo -e " TLS 자동설정 = ${cyan}켬$none"
		else
			echo -e " TLS 자동설정 = $red끔$none"
		fi
		echo
	fi
}
change_path_config() {
	if [[ $v2ray_transport == [45] ]] && [[ $caddy && $is_path ]]; then
		echo
		while :; do
			echo -e "${magenta}사용할 경로$none를 입력해 주세요. 예) /szkorean인 경우 szkorean 으로 입력하면 됩니다."
			read -p "$(echo -e "(기존 경로: [${cyan}/${path}$none]):")" new_path
			[[ -z $new_path ]] && error && continue

			case $new_path in
			$path)
				echo
				echo -e " 기존 경로와 동일합니다... 다른 경로로 수정해 주세요."
				echo
				error
				;;
			*[/$]*)
				echo
				echo -e " 경로에 $red / $none或$red $ $none 특수기호를 포함할 수 없습니다.... "
				echo
				error
				;;
			*)
				echo
				echo
				echo -e "$yellow 경로 = ${cyan}/${new_path}$none"
				echo "----------------------------------------------------------------"
				echo
				break
				;;
			esac
		done
		pause
		backup_config path
		path=$new_path
		caddy_config
		config
		clear
		view_v2ray_config_info
		# download_v2ray_config_ask
	elif [[ $v2ray_transport == [45] ]] && [[ $caddy ]]; then
		path_config_ask
		if [[ $new_path ]]; then
			backup_config +path
			path=$new_path
			proxy_site=$new_proxy_site
			is_path=true
			caddy_config
			config
			clear
			view_v2ray_config_info
			# download_v2ray_config_ask
		else
			echo
			echo
			echo " 사이트 위장 및 경로 설정을 취소하였습니다."
			echo
			echo
		fi
	else
		echo
		echo -e "$red 죄송합니다...수정할 수 없습니다...$none"
		echo
		echo -e " 참고.. 경로 수정은 전송 프로토콜이 ${yellow}WebSocket + TLS$none 또는 ${yellow}HTTP/2$none 이고$yellow TLS 자동설정 = 켬$none 상태에서만 가능합니다."
		echo
		echo -e " 기존 전송 프로토콜: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
		if [[ $caddy ]]; then
			echo -e " TLS 자동설정 = ${cyan}켬$none"
		else
			echo -e " TLS 자동설정 = $red끔$none"
		fi
		echo
		change_v2ray_transport_ask
	fi

}
change_proxy_site_config() {
	if [[ $v2ray_transport == [45] ]] && [[ $caddy && $is_path ]]; then
		echo
		while :; do
			echo -e " ${magenta}정확한$none ${cyan}사이트 주소$none를 입력하여 ${cyan}사이트를 위장$none하세요. https://smartstore.naver.com/nyintl으로"
			echo -e "예를 들면... 만약 기존에 설정한 도메인이$green $domain $none인 경우, 위장할 사이트는 https://smartstore.naver.com/nyintl이 됩니다."
			echo -e "설정한 도메인으로 접속하면... 표시되는 내용은 https://smartstore.naver.com/nyintl의 내용이 표시됩니다."
			echo -e "Reverse Proxy로 이해하시면 됩니다.."
			echo -e "만약 위장에 성공하지 못하는 경우, v2ray config 으로 위장 사이트를 변경하세요."
			read -p "$(echo -e "(기존 위장 사이트 주소: [${cyan}${proxy_site}$none]):")" new_proxy_site
			[[ -z $new_proxy_site ]] && error && continue

			case $new_proxy_site in
			*[#$]*)
				echo
				echo -e " 위장 사이트 주소에$red # $none또는$red $ $none특수기호를 포함하지 못합니다.... "
				echo
				error
				;;
			*)
				echo
				echo
				echo -e "$yellow 위장된 사이트 주소 = ${cyan}${new_proxy_site}$none"
				echo "----------------------------------------------------------------"
				echo
				break
				;;
			esac
		done
		pause
		backup_config proxy_site
		proxy_site=$new_proxy_site
		caddy_config
		echo
		echo
		echo " 수정에 성공한 것 같습니다..."
		echo
		echo -e " ${cyan}https://${domain}$none 주소를 열어서 적용  확인해 보세요"
		echo
		echo
	elif [[ $v2ray_transport == [45] ]] && [[ $caddy ]]; then
		path_config_ask
		if [[ $new_path ]]; then
			backup_config +path
			path=$new_path
			proxy_site=$new_proxy_site
			is_path=true
			caddy_config
			config
			clear
			view_v2ray_config_info
			# download_v2ray_config_ask
		else
			echo
			echo
			echo " 사이트 위장 및 경로 설정을 취소하였습니다."
			echo
			echo
		fi
	else
		echo
		echo -e "$red 죄송합니다... 수정할 수 없습니다...$none"
		echo
		echo -e " 참고.. 위장사이트 주소 수정은 전송 프로토콜이 ${yellow}WebSocket + TLS$none 또는 ${yellow}HTTP/2$none 인 경우 및$yellow TLS 자동설정 = 켬$none인 상태에서만 가능합니다."
		echo
		echo -e " 기존 전송 프로토콜: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
		if [[ $caddy ]]; then
			echo -e " TLS 자동설정 = ${cyan}켬$none"
		else
			echo -e " TLS 자동설정 = $red끔$none"
		fi
		echo
		change_v2ray_transport_ask
	fi

}
domain_check() {
	# test_domain=$(dig $new_domain +short)
	test_domain=$(ping $new_domain -c 1 | grep -oE -m1 "([0-9]{1,3}\.){3}[0-9]{1,3}")
	if [[ $test_domain != $ip ]]; then
		echo
		echo -e "$red 도메인명 해석 테스트에 오류가 발생했습니다....$none"
		echo
		echo -e " 도메인명: $yellow$new_domain$none 이 아래 IP로 해석되지 않습니다: $cyan$ip$none"
		echo
		echo -e " 도메인이 아래 도메인으로 해석됩니다 : $cyan$test_domain$none"
		echo
		echo "참고...만약 도메인명이 Cloudflare를 사용해서 해석되는 경우, Status 부분에서 이미지를 클릭하여 회색으로 바꾸세요."
		echo
		exit 1
	fi
}
disable_path() {
	if [[ $v2ray_transport == [45] ]] && [[ $caddy && $is_path ]]; then
		echo

		while :; do
			echo -e " ${yellow}사이트 위장 및 경로 설정${none}을 끄시겠습니까? [${magenta}Y/N$none]"
			read -p "$(echo -e "(기본값 [${cyan}N$none]):") " y_n
			[[ -z "$y_n" ]] && y_n="n"
			if [[ "$y_n" == [Yy] ]]; then
				echo
				echo
				echo -e "$yellow 사이트 위장 및 경로 설정 끔 = $cyan예$none"
				echo "----------------------------------------------------------------"
				echo
				pause
				backup_config -path
				is_path=''
				caddy_config
				config
				clear
				view_v2ray_config_info
				# download_v2ray_config_ask
				break
			elif [[ "$y_n" == [Nn] ]]; then
				echo
				echo -e " $green 사이트 위장 및 경로 설정이 취소되었습니다...$none"
				echo
				break
			else
				error
			fi

		done
	else
		echo
		echo -e "$red 죄송합니다...수정할 수 없습니다...$none"
		echo
		echo -e " 기존 전송 프로토콜: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
		if [[ $caddy ]]; then
			echo -e " TLS 자동설정 = ${cyan}켬$none"
		else
			echo -e " TLS 자동설정 = $red끔$none"
		fi
		echo
		if [[ $is_path ]]; then
			echo -e " 경로 설정 = ${cyan}켬$none"
		else
			echo -e " 경로 설정 = $red끔$none"
		fi
		echo
		echo -e " 반드시 WebSocket + TLS 또는 HTTP/2 전송 프로토콜 사용 및 TLS 자동설정 = ${cyan}켬$none, 경로 설정 = ${cyan}켬$none, 상태인 경우에만 수정 가능합니다."
		echo

	fi
}
blocked_hosts() {
	if [[ $ban_ad ]]; then
		local _info="$green켜짐$none"
	else
		local _info="$red꺼짐$none"
	fi
	_opt=''
	while :; do
		echo
		echo -e "$yellow 1. $none 광고 차단 켬"
		echo
		echo -e "$yellow 2. $none 광고 차단 끔"
		echo
		echo "참고: 광고 차단은 기본적으로 도메인 차단입니다.. 따라서 사이트 브라우징 시 일부분이 공백으로 표시되거나 문제가 발생할 수 있습니다."
		echo
		echo "문제 보고 및 차단 도메인 추가 : https://github.com/233boy/v2ray/issues"
		echo
		echo -e "기존 광고 차단 상태: $_info"
		echo
		read -p "$(echo -e "선택하세요 [${magenta}1-2$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				if [[ $ban_ad ]]; then
					echo
					echo -e " (광고 차단 상태: $_info) 이미 켜져 있습니다."
					echo
				else
					echo
					echo
					echo -e "$yellow 광고 차단 = $cyan켬$none"
					echo "----------------------------------------------------------------"
					echo
					pause
					backup_config +ad
					ban_ad=true
					config
					echo
					echo
					echo -e "$green 광고 차단이 켜졌습니다...만약 이상이 발생하면 이 기능을 끄세요..$none"
					echo
				fi
				break
				;;
			2)
				if [[ $ban_ad ]]; then
					echo
					echo
					echo -e "$yellow 광고 차단 = $cyan끔$none"
					echo "----------------------------------------------------------------"
					echo
					pause
					backup_config -ad
					ban_ad=''
					config
					echo
					echo
					echo -e "$red 광고 차단 기능이 껴졌습니다...원하시면 아무 때나 다시 켤 수 있습니다..$none"
					echo
				else
					echo
					echo -e " (광고 차단 상태: $_info) 이미 켜져 있습니다."
					echo
				fi
				break
				;;
			*)
				error
				;;
			esac
		fi
	done

}
change_v2ray_alterId() {
	echo
	while :; do
		echo -e " ${yellow}alterId${none} 값을 입력해 주세요 [${magenta}0-65535$none]"
		read -p "$(echo -e "(기존 값: ${cyan}$alterId$none):") " new_alterId
		[[ -z $new_alterId ]] && error && continue
		case $new_alterId in
		$alterId)
			echo
			echo -e " 기존 alterId와 동일합니다...다르게 입력해주세요."
			echo
			error
			;;
		[0-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			echo
			echo
			echo -e "$yellow alterId = $cyan$new_alterId$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config alterId
			alterId=$new_alterId
			config
			clear
			view_v2ray_config_info
			# download_v2ray_config_ask
			break
			;;
		*)
			error
			;;
		esac
	done
}

custom_uuid() {
	echo
	while :; do
		echo -e "$yello임의의 UUID$none를 입력하세요...(${cyan}UUID 형식은 반드시 지켜야 합니다!!!$none)"
		read -p "$(echo -e "(기존 UUID: ${cyan}${v2ray_id}$none)"): " myuuid
		[ -z "$myuuid" ] && error && continue
		case $myuuid in
		$v2ray_id)
			echo
			echo -e " 기존 UUID와 동일합니다...다르게 입력하세요."
			echo
			error
			;;
		*[/$]* | *\&*)
			echo
			echo -e " UUID에$red / $none또는$red $ $none또는$red & $none 특수기호를 포함할 수 없습니다.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow UUID = $cyan$myuuid$none"
			echo
			echo -e " 만약 UUID 형식이 올바르지 않으면.. V2Ray가 뻗을 수 있습니다...$cyan v2ray reuuid$none로 되살리세요"
			echo "----------------------------------------------------------------"
			echo
			pause
			uuid=$myuuid
			backup_config uuid
			v2ray_id=$uuid
			config
			clear
			view_v2ray_config_info
			# download_v2ray_config_ask
			break
			;;
		esac
	done
}
v2ray_service() {
	while :; do
		echo
		echo -e "$yellow 1. $none V2Ray 시작"
		echo
		echo -e "$yellow 2. $none V2Ray 중지"
		echo
		echo -e "$yellow 3. $none V2Ray 재시작"
		echo
		echo -e "$yellow 4. $none 방문이력 보기"
		echo
		echo -e "$yellow 5. $none 오류이력 보기"
		echo
		read -p "$(echo -e "선택하세요. [${magenta}1-5$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				start_v2ray
				break
				;;
			2)
				stop_v2ray
				break
				;;
			3)
				restart_v2ray
				break
				;;
			4)
				view_v2ray_log
				break
				;;
			5)
				view_v2ray_error_log
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
start_v2ray() {
	if [[ $v2ray_pid ]]; then
		echo
		echo -e "${green} V2Ray 이미 실행 중입니다...다시 시작할 필요가 없습니다$none"
		echo
	else

		# systemctl start v2ray
		service v2ray start >/dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			echo
			echo -e "${red} V2Ray 시작 실패!$none"
			echo
		else
			echo
			echo -e "${green} V2Ray가 시작되었습니다.$none"
			echo
		fi

	fi
}
stop_v2ray() {
	if [[ $v2ray_pid ]]; then
		# systemctl stop v2ray
		service v2ray stop >/dev/null 2>&1
		echo
		echo -e "${green} V2Ray가 정지되었습니다.$none"
		echo
	else
		echo
		echo -e "${red} V2Ray가 실행되고 있지 않습니다.$none"
		echo
	fi
}
restart_v2ray() {
	# systemctl restart v2ray
	service v2ray restart >/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		echo
		echo -e "${red} V2Ray 재시작 실패!$none"
		echo
	else
		echo
		echo -e "${green} V2Ray 재시작 성공$none"
		echo
	fi
}
view_v2ray_log() {
	echo
	echo -e "$green 按 Ctrl + C 를 누르면 종료됩니다...$none"
	echo
	tail -f /var/log/v2ray/access.log
}
view_v2ray_error_log() {
	echo
	echo -e "$green 按 Ctrl + C 를 누르면 종료됩니다...$none"
	echo
	tail -f /var/log/v2ray/error.log
}
download_v2ray_config() {
	while :; do
		echo
		echo -e "$yellow 1. $none V2Ray 클라이언트 설정 문서 직접 다운로드(Xshell만 지원)"
		echo
		echo -e "$yellow 2. $none V2Ray 클라이언트 설정 문서 다운로드 링크 생성"
		echo
		echo -e "$yellow 3. $none V2Ray 설정 정보 링크 생성"
		echo
		echo -e "$yellow 4. $none V2Ray 설정 QR코드 링크 생성"
		echo
		read -p "$(echo -e "선택하세요. [${magenta}1-4$none]:")" other_opt
		if [[ -z $other_opt ]]; then
			error
		else
			case $other_opt in
			1)
				get_v2ray_config
				break
				;;
			2)
				get_v2ray_config_link
				break
				;;
			3)
				get_v2ray_config_info_link
				break
				;;
			4)
				get_v2ray_config_qr_link
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
get_v2ray_config() {
	config
	echo
	echo "  만약 사용하시는 SSH 클라이언트가 Xshell이 아니면 V2Ray 클라이언트 설정 문서 다운로드는 클라이언트를 다운시킬 수도 있습니다."
	echo
	while :; do
		read -p "$(echo -e "현재 Xshell를 사용중입니까? [${magenta}Y$none]:")" is_xshell
		if [[ -z $is_xshell ]]; then
			error
		else
			if [[ $is_xshell == [yY] ]]; then
				echo
				echo "다운로드를 시작합니다. V2Ray 클라이언트 설정 문서를 저장할 위치를 선택하세요."
				echo
				# sz /etc/v2ray/233blog_v2ray.zip
				local tmpfile="/tmp/szkorean_v2ray_config_$RANDOM.json"
				cp -f $v2ray_client_config $tmpfile
				sz $tmpfile
				echo
				echo
				echo -e "$green 다운로드 성공...$none"
				echo
				# echo -e "$yellow 解压密码 = ${cyan}233blog.com$none"
				# echo
				echo -e "$yellow SOCKS listen 포트 = ${cyan}2333${none}"
				echo
				echo -e "${yellow} HTTP listen 포트 = ${cyan}6666$none"
				echo
				echo "V2Ray 클라이언트 사용 강좌 (중국어): https://233v2.com/post/4/"
				echo
				break
			else
				error
			fi
		fi
	done
	[[ -f $tmpfile ]] && rm -rf $tmpfile

}
get_v2ray_config_link() {
	_load client_file.sh
	_get_client_file
}
create_v2ray_config_text() {

	get_transport_args

	echo
	echo
	echo "---------- V2Ray 설정 정보 -------------"
	if [[ $v2ray_transport == [45] ]]; then
		if [[ ! $caddy ]]; then
			echo
			echo " 경고! TLS 자동설정 강좌를 참고하세요 (중국어): https://233v2.com/post/3/"
		fi
		echo
		echo "주소  (Address) = ${domain}"
		echo
		echo "포트 (Port) = 443"
		echo
		echo "사용자ID (User ID / UUID) = ${v2ray_id}"
		echo
		echo "대체ID (Alter Id) = ${alterId}"
		echo
		echo "전송 프로토콜 (Network) = ${net}"
		echo
		echo "위장 종류 (header type) = ${header}"
		echo
		echo "위장 도메인 (host) = ${domain}"
		echo
		echo "경로 (path) = ${_path}"
		echo
		echo "TLS (Enable TLS) = 켬"
		echo
		if [[ $ban_ad ]]; then
			echo " 참고: 광고 차단 켜진 상태입니다.."
			echo
		fi
	else
		[[ -z $ip ]] && get_ip
		echo
		echo "주소 (Address) = ${ip}"
		echo
		echo "포트 (Port) = $v2ray_port"
		echo
		echo "사용자ID (User ID / UUID) = ${v2ray_id}"
		echo
		echo "대체ID (Alter Id) = ${alterId}"
		echo
		echo "전송 프로토콜 (Network) = ${net}"
		echo
		echo "위장 종류 (header type) = ${header}"
		echo
	fi
	if [[ $v2ray_transport -ge 18 ]] && [[ $ban_ad ]]; then
		echo "참고: 동적포트가 켜진 상태입니다...광고 차단이 켜진 상태입니다..."
		echo
	elif [[ $v2ray_transport -ge 18 ]]; then
		echo "참고: 동적포트가 켜진 상태입니다..."
		echo
	elif [[ $ban_ad ]]; then
		echo "참고: 광고 차단이 켜진 상태입니다.."
		echo
	fi
	echo "---------- END -------------"
	echo
	echo "V2Ray 클라이언트 사용 강좌(중국어): https://233v2.com/post/4/"
	echo
}
get_v2ray_config_info_link() {
	echo
	echo -e "$green 링크 생성중입니다.... 잠시만 기다리세요....$none"
	echo
	create_v2ray_config_text >/tmp/szkorean_v2ray.txt
	local random=$(echo $RANDOM-$RANDOM-$RANDOM | base64 -w 0)
	local link=$(curl -s --upload-file /tmp/szkorean_v2ray.txt "https://transfer.sh/${random}_szkorean_v2ray.txt")
	if [[ $link ]]; then
		echo
		echo "---------- V2Ray 설정 정보 링크-------------"
		echo
		echo -e "$yellow 링크 = $cyan$link$none"
		echo
		echo -e " V2Ray 클라이언트 사용 강좌(중국어): https://233v2.com/post/4/"
		echo
		echo "참고...링크는 14일간 사용 가능합니다..."
		echo
		echo "알림...특별한 상황이 아니라면 링크를 공유하지 마세요...."
		echo
	else
		echo
		echo -e "$red 오류가 발생했습니다. 다시 시도해주세요.$none"
		echo
	fi
	rm -rf /tmp/szkorean_v2ray.txt
}
get_v2ray_config_qr_link() {

	create_vmess_URL_config

	_load qr.sh
	_qr_create
}
get_v2ray_vmess_URL_link() {
	create_vmess_URL_config
	local vmess="vmess://$(cat /etc/v2ray/vmess_qr.json | base64 -w 0)"
	echo
	echo "---------- V2Ray vmess URL / V2RayNG v0.4.1+ / V2RayN v2.1+ / 일부 클라이언트에만 사용 가능 -------------"
	echo
	echo -e ${cyan}$vmess${none}
	echo
	rm -rf /etc/v2ray/vmess_qr.json
}
other() {
	while :; do
		echo
		echo -e "$yellow 1. $none BBR 설치"
		echo
		echo -e "$yellow 2. $none LotServer(가속기)설치"
		echo
		echo -e "$yellow 3. $none LotServer(가속기)제거"
		echo
		read -p "$(echo -e "선택 [${magenta}1-3$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				install_bbr
				break
				;;
			2)
				install_lotserver
				break
				;;
			3)
				uninstall_lotserver
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
install_bbr() {
	local test1=$(sed -n '/net.ipv4.tcp_congestion_control/p' /etc/sysctl.conf)
	local test2=$(sed -n '/net.core.default_qdisc/p' /etc/sysctl.conf)
	if [[ $test1 == "net.ipv4.tcp_congestion_control = bbr" && $test2 == "net.core.default_qdisc = fq" ]]; then
		echo
		echo -e "$green BBR을 이미 사용 중입니다...다시 설치할 필요 없습니다.$none"
		echo
	else
		_load bbr.sh
		_try_enable_bbr
		[[ ! $enable_bbr ]] && bash <(curl -s -L https://github.com/teddysun/across/raw/master/bbr.sh)
	fi
}
install_lotserver() {
	# https://moeclub.org/2017/03/08/14/
	wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh"
	bash /tmp/appex.sh 'install'
	rm -rf /tmp/appex.sh
}
uninstall_lotserver() {
	# https://moeclub.org/2017/03/08/14/
	wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh"
	bash /tmp/appex.sh 'uninstall'
	rm -rf /tmp/appex.sh
}

open_port() {
	if [[ $cmd == "apt-get" ]]; then
		if [[ $1 != "multiport" ]]; then
			# if [[ $cmd == "apt-get" ]]; then
			iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
			iptables -I INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT
			ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
			ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT

			# iptables-save >/etc/iptables.rules.v4
			# ip6tables-save >/etc/iptables.rules.v6
			# else
			# 	firewall-cmd --permanent --zone=public --add-port=$1/tcp
			# 	firewall-cmd --permanent --zone=public --add-port=$1/udp
			# 	firewall-cmd --reload
			# fi
		else
			# if [[ $cmd == "apt-get" ]]; then
			local multiport="${v2ray_dynamic_port_start_input}:${v2ray_dynamic_port_end_input}"
			iptables -I INPUT -p tcp --match multiport --dports $multiport -j ACCEPT
			iptables -I INPUT -p udp --match multiport --dports $multiport -j ACCEPT
			ip6tables -I INPUT -p tcp --match multiport --dports $multiport -j ACCEPT
			ip6tables -I INPUT -p udp --match multiport --dports $multiport -j ACCEPT

			# iptables-save >/etc/iptables.rules.v4
			# ip6tables-save >/etc/iptables.rules.v6
			# else
			# 	local multi_port="${v2ray_dynamic_port_start_input}-${v2ray_dynamic_port_end_input}"
			# 	firewall-cmd --permanent --zone=public --add-port=$multi_port/tcp
			# 	firewall-cmd --permanent --zone=public --add-port=$multi_port/udp
			# 	firewall-cmd --reload
			# fi
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
update() {
	while :; do
		echo
		echo -e "$yellow 1. $none V2Ray 프로그램 업데이트"
		echo
		echo -e "$yellow 2. $none V2Ray 관리스크립트 업데이트"
		echo
		read -p "$(echo -e "선택하세요 [${magenta}1-2$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				update_v2ray
				break
				;;
			2)
				update_v2ray.sh
				exit
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
update_v2ray() {
	_load download-v2ray.sh
	_update_v2ray_version
}
update_v2ray.sh() {
	if [[ $_test ]]; then
		local latest_version=$(curl -H 'Cache-Control: no-cache' -s -L "https://raw.githubusercontent.com/233boy/v2ray/test/v2ray.sh" | grep '_version' -m1 | cut -d\" -f2)
	else
		local latest_version=$(curl -H 'Cache-Control: no-cache' -s -L "https://raw.githubusercontent.com/233boy/v2ray/master/v2ray.sh" | grep '_version' -m1 | cut -d\" -f2)
	fi

	if [[ ! $latest_version ]]; then
		echo
		echo -e " $red V2Ray 최신버전 가져오기 실패!!!$none"
		echo
		echo -e "  아래 명령이 실행가능한지 확인하세요 : $green echo 'nameserver 8.8.8.8' >/etc/resolv.conf $none"
		echo
		echo " 그 뒤에 다시 실행해 보시기 바랍니다...."
		echo
		exit 1
	fi

	if [[ $latest_version == $_version ]]; then
		echo
		echo -e "$green 새 버전이 없습니다. $none"
		echo
	else
		echo
		echo -e " $green 새 버전이 있습니다...  업데이트 하겠습니다.......$none"
		echo
		cd /etc/v2ray/233boy/v2ray
		git pull
		cp -f /etc/v2ray/233boy/v2ray/v2ray.sh $_v2ray_sh
		chmod +x $_v2ray_sh
		echo
		echo -e "$green 갱신 완료... V2Ray 관리 스크립트 버전: ${cyan}$latest_version$none"
		echo
	fi

}
uninstall_v2ray() {
	_load uninstall.sh
}
config() {
	_load config.sh

	if [[ $v2ray_port == "80" ]]; then
		if [[ $cmd == "yum" ]]; then
			[[ $(pgrep "httpd") ]] && systemctl stop httpd >/dev/null 2>&1
			[[ $(command -v httpd) ]] && yum remove httpd -y >/dev/null 2>&1
		else
			[[ $(pgrep "apache2") ]] && service apache2 stop >/dev/null 2>&1
			[[ $(command -v apache2) ]] && apt-get remove apache2* -y >/dev/null 2>&1
		fi
	fi
	do_service restart v2ray
}
backup_config() {
	for keys in $*; do
		case $keys in
		v2ray_transport)
			sed -i "18s/=$v2ray_transport/=$v2ray_transport_opt/" $backup
			;;
		v2ray_port)
			sed -i "21s/=$v2ray_port/=$v2ray_port_opt/" $backup
			;;
		uuid)
			sed -i "24s/=$v2ray_id/=$uuid/" $backup
			;;
		alterId)
			sed -i "27s/=$alterId/=$new_alterId/" $backup
			;;
		v2ray_dynamicPort_start)
			sed -i "30s/=$v2ray_dynamicPort_start/=$v2ray_dynamic_port_start_input/" $backup
			;;
		v2ray_dynamicPort_end)
			sed -i "33s/=$v2ray_dynamicPort_end/=$v2ray_dynamic_port_end_input/" $backup
			;;
		domain)
			sed -i "36s/=$domain/=$new_domain/" $backup
			;;
		caddy)
			sed -i "39s/=/=true/" $backup
			;;
		+ss)
			sed -i "42s/=/=true/; 45s/=$ssport/=$new_ssport/; 48s/=$sspass/=$new_sspass/; 51s/=$ssciphers/=$new_ssciphers/" $backup
			;;
		-ss)
			sed -i "42s/=true/=/" $backup
			;;
		ssport)
			sed -i "45s/=$ssport/=$new_ssport/" $backup
			;;
		sspass)
			sed -i "48s/=$sspass/=$new_sspass/" $backup
			;;
		ssciphers)
			sed -i "51s/=$ssciphers/=$new_ssciphers/" $backup
			;;
		+ad)
			sed -i "54s/=/=true/" $backup
			;;
		-ad)
			sed -i "54s/=true/=/" $backup
			;;
		+path)
			sed -i "57s/=/=true/; 60s/=$path/=$new_path/; 63s#=$proxy_site#=$new_proxy_site#" $backup
			;;
		-path)
			sed -i "57s/=true/=/" $backup
			;;
		path)
			sed -i "60s/=$path/=$new_path/" $backup
			;;
		proxy_site)
			sed -i "63s#=$proxy_site#=$new_proxy_site#" $backup
			;;
		+socks)
			sed -i "66s/=/=true/; 69s/=$socks_port/=$new_socks_port/; 72s/=$socks_username/=$new_socks_username/; 75s/=$socks_userpass/=$new_socks_userpass/;" $backup
			;;
		-socks)
			sed -i "66s/=true/=/" $backup
			;;
		socks_port)
			sed -i "69s/=$socks_port/=$new_socks_port/" $backup
			;;
		socks_username)
			sed -i "72s/=$socks_username/=$new_socks_username/" $backup
			;;
		socks_userpass)
			sed -i "75s/=$socks_userpass/=$new_socks_userpass/" $backup
			;;
		+mtproto)
			sed -i "78s/=/=true/; 81s/=$mtproto_port/=$new_mtproto_port/; 84s/=$mtproto_secret/=$new_mtproto_secret/" $backup
			;;
		-mtproto)
			sed -i "78s/=true/=/" $backup
			;;
		mtproto_port)
			sed -i "81s/=$mtproto_port/=$new_mtproto_port/" $backup
			;;
		mtproto_secret)
			sed -i "84s/=$mtproto_secret/=$new_mtproto_secret/" $backup
			;;
		+bt)
			sed -i "87s/=/=true/" $backup
			;;
		-bt)
			sed -i "87s/=true/=/" $backup
			;;
		esac
	done

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
	[[ -z $ip ]] && echo -e "\n$red 이 스크립트가 좀 구려요..$none\n" && exit
}

error() {

	echo -e "\n$red 입력 오류！$none\n"

}

pause() {

	read -rsp "$(echo -e "$green Enter 키$none를 눌러 계속하세요....또는$red Ctrl + C$none를 눌러 취소하세요.")" -d $'\n'
	echo
}
do_service() {
	if [[ $systemd ]]; then
		systemctl $1 $2
	else
		service $2 $1
	fi
}
_help() {
	echo
	echo "........... V2Ray 관리 스크립트 정보 by 233v2.com .........."
	echo -e "
	${green}v2ray menu $none V2Ray 관리 (v2ray 입력과 동일)

	${green}v2ray info $none V2Ray 설정 정보 표시

	${green}v2ray config $none V2Ray 설정 수정

	${green}v2ray link $none V2Ray 클라이언트 설정 정보 링크 생성

	${green}v2ray textlink $none V2Ray 설정 정보 링크 생성

	${green}v2ray qr $none V2Ray 설정 QR코드 링크 생성

	${green}v2ray ss $none Shadowsocks 설정 수정

	${green}v2ray ssinfo $none Shadowsocks 설정 정보 표시

	${green}v2ray ssqr $none Shadowsocks 설정 QR코드 링크 생성

	${green}v2ray status $none V2Ray 실행상태 표시

	${green}v2ray start $none V2Ray 시작

	${green}v2ray stop $none V2Ray 중지

	${green}v2ray restart $none V2Ray 재시작

	${green}v2ray log $none V2Ray 실행이력 표시

	${green}v2ray update $none V2Ray 업데이트

	${green}v2ray update.sh $none V2Ray 관리 스크립트 업데이트

	${green}v2ray uninstall $none V2Ray 제거
"
}
menu() {
	clear
	while :; do
		echo
		echo "........... V2Ray 관리스크립트 $_version by 233v2.com .........."
		echo
		echo -e "## V2Ray 버전: $cyan$v2ray_ver$none  /  V2Ray 상태: $v2ray_status ##"
		echo
		echo "도움말 (중국어): https://233v2.com/post/1/"
		echo
		echo "문제보고 (중국어): https://github.com/233boy/v2ray/issues"
		echo
		echo "텔레그램 톡방 (중국어): https://t.me/blog233"
		echo
		echo "스크립트 작성자에게 기부하기 (현재 연결불가): https://233v2.com/donate/"
		echo
		echo "V2Ray에 기부하기: https://www.v2ray.com/ko/welcome/donate.html"
		echo
		echo -e "$yellow  1. $none V2Ray 설정 보기"
		echo
		echo -e "$yellow  2. $none V2Ray 설정 수정"
		echo
		echo -e "$yellow  3. $none V2Ray V2Ray 설정 보기 / 설정 정보 링크 생성 / QR코드 링크 생성"
		echo
		echo -e "$yellow  4. $none Shadowsocks Shadowsocks 설정 보기 / QR코드 생성"
		echo
		echo -e "$yellow  5. $none Shadowsocks 설정 수정"
		echo
		echo -e "$yellow  6. $none MTProto 설정 보기 / MTProto 설정 수정"
		echo
		echo -e "$yellow  7. $none Socks5 설정 보기 / Socks5 설정 수정"
		echo
		echo -e "$yellow  8. $none 시작 / 중지 / 재시작 / 로그 보기"
		echo
		echo -e "$yellow  9. $none V2Ray 업데이트 / V2Ray 관리 스크립트 업데이트"
		echo
		echo -e "$yellow 10. $none V2Ray 제거"
		echo
		echo -e "$yellow 11. $none 기타"
		echo
		echo -e "주의.. 만약 선택사항을 고르지 않으려면 $yellow Ctrl + C $none를 눌러서 나가시면 됩니다."
		echo
		read -p "$(echo -e "메뉴 선택 [${magenta}1-11$none]:")" choose
		if [[ -z $choose ]]; then
			exit 1
		else
			case $choose in
			1)
				view_v2ray_config_info
				break
				;;
			2)
				change_v2ray_config
				break
				;;
			3)
				download_v2ray_config
				break
				;;
			4)
				get_shadowsocks_config
				break
				;;
			5)
				change_shadowsocks_config
				break
				;;
			6)
				_load mtproto.sh
				_mtproto_main
				break
				;;
			7)
				_load socks.sh
				_socks_main
				break
				;;
			8)
				v2ray_service
				break
				;;
			9)
				update
				break
				;;
			10)
				uninstall_v2ray
				break
				;;
			11)
				other
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
args=$1
[ -z $1 ] && args="menu"
case $args in
menu)
	menu
	;;
i | info)
	view_v2ray_config_info
	;;
c | config)
	change_v2ray_config
	;;
l | link)
	get_v2ray_config_link
	;;
L | infolink)
	get_v2ray_config_info_link
	;;
q | qr)
	get_v2ray_config_qr_link
	;;
s | ss)
	change_shadowsocks_config
	;;
S | ssinfo)
	view_shadowsocks_config_info
	;;
Q | ssqr)
	get_shadowsocks_config_qr_link
	;;
socks)
	_load socks.sh
	_socks_main
	;;
socksinfo)
	_load socks.sh
	_view_socks_info
	;;
tg)
	_load mtproto.sh
	_mtproto_main
	;;
tginfo)
	_load mtproto.sh
	_view_mtproto_info
	;;
bt)
	_load bt.sh
	_ban_bt_main
	;;
status)
	echo
	if [[ $v2ray_transport == [45] && $caddy ]]; then
		echo -e " V2Ray 상태: $v2ray_status  /  Caddy 상태: $caddy_run_status"
	else
		echo -e " V2Ray 상태: $v2ray_status"
	fi
	echo
	;;
start)
	start_v2ray
	;;
stop)
	stop_v2ray
	;;
restart)
	[[ $v2ray_transport == [45] && $caddy ]] && do_service restart caddy
	restart_v2ray
	;;
reload)
	config
	[[ $v2ray_transport == [45] && $caddy ]] && caddy_config
	clear
	view_v2ray_config_info
	;;
time)
	date -s "$(curl -sI g.cn | grep Date | cut -d' ' -f3-6)Z"
	;;
log)
	view_v2ray_log
	;;
url | URL)
	get_v2ray_vmess_URL_link
	;;
u | update)
	update_v2ray
	;;
U | update.sh)
	update_v2ray.sh
	exit
	;;
un | uninstall)
	uninstall_v2ray
	;;
reinstall)
	uninstall_v2ray
	if [[ $is_uninstall_v2ray ]]; then
		cd
		cd - >/dev/null 2>&1
		bash <(curl -s -L https://git.io/v2ray.sh)
	fi
	;;
[aA][Ii] | [Dd])
	change_v2ray_alterId
	;;
[aA][Ii][aA][Ii] | [Dd][Dd])
	custom_uuid
	;;
reuuid)
	backup_config uuid
	v2ray_id=$uuid
	config
	clear
	view_v2ray_config_info
	# download_v2ray_config_ask
	;;
v | version)
	echo
	echo -e " V2Ray 버전: ${green}$v2ray_ver$none  /  V2Ray 관리스크립트 버전: ${cyan}$_version$none"
	echo
	;;
bbr)
	other
	;;
help | *)
	_help
	;;
esac
