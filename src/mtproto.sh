_view_mtproto_info() {
	if [[ $mtproto ]]; then
		_mtproto_info
	else
		_mtproto_ask
	fi
}
_mtproto_info() {
	[[ -z $ip ]] && get_ip
	echo
	echo "---------- Telegram MTProto 설정 정보 -------------"
	echo
	echo -e "$yellow 서버 (Hostname) = $cyan${ip}$none"
	echo
	echo -e "$yellow 포트 (Port) = $cyan$mtproto_port$none"
	echo
	echo -e "$yellow 키 (Secret) = $cyan$mtproto_secret$none"
	echo
	echo -e "$yellow Telegram 프록스 설정 링크 = ${cyan}https://t.me/proxy?server=${ip}&port=${mtproto_port}&secret=${mtproto_secret}$none"
	echo
}
_mtproto_main() {
	if [[ $mtproto ]]; then

		while :; do
			echo
			echo -e "$yellow 1. $none Telegram MTProto 설정 정보 보기"
			echo
			echo -e "$yellow 2. $none Telegram MTProto 포트 변경"
			echo
			echo -e "$yellow 3. $none Telegram MTProto 키 변경"
			echo
			echo -e "$yellow 4. $none Telegram MTProto 끄기"
			echo
			read -p "$(echo -e "선택해주세요 [${magenta}1-4$none]:")" _opt
			if [[ -z $_opt ]]; then
				error
			else
				case $_opt in
				1)
					_mtproto_info
					break
					;;
				2)
					change_mtproto_port
					break
					;;
				3)
					change_mtproto_secret
					break
					;;
				4)
					disable_mtproto
					break
					;;
				*)
					error
					;;
				esac
			fi

		done
	else
		_mtproto_ask
	fi
}
_mtproto_ask() {
	echo
	echo
	echo -e " $red Telegram MTProto$none를 설정하지 않았습니다. 지금 설명하실 수 있습니다.^_^"
	echo
	echo
	new_mtproto_secret="dd$(date | md5sum | cut -c-30)"
	while :; do
		echo -e "${yellow}Telegram MTProto${none}를 설정하시겠습니까? [${magenta}Y/N$none]"
		read -p "$(echo -e "(기본값 [${cyan}N$none]):") " new_mtproto
		[[ -z "$new_mtproto" ]] && new_mtproto="n"
		if [[ "$new_mtproto" == [Yy] ]]; then
			echo
			mtproto=true
			mtproto_port_config
			pause
			open_port $new_mtproto_port
			backup_config +mtproto
			mtproto_port=$new_mtproto_port
			mtproto_secret=$new_mtproto_secret
			config
			clear
			_mtproto_info
			break
		elif [[ "$new_mtproto" == [Nn] ]]; then
			echo
			echo -e " $green Telegram MTProto 설정이 취소되었습니다....$none"
			echo
			break
		else
			error
		fi

	done
}
disable_mtproto() {
	echo

	while :; do
		echo -e "${yellow}Telegram MTProto${none}를 끄시겠습니까? [${magenta}Y/N$none]"
		read -p "$(echo -e "(기본값 [${cyan}N$none]):") " y_n
		[[ -z "$y_n" ]] && y_n="n"
		if [[ "$y_n" == [Yy] ]]; then
			echo
			echo
			echo -e "$yellow Telegram MTProto 끄기= $cyan예$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config -mtproto
			del_port $mtproto_port
			mtproto=''
			config
			echo
			echo
			echo
			echo -e "$green Telegram MTProto가 꺼졌습니다... 필요하면 다시 켜실 수 있습니다.$none"
			echo
			break
		elif [[ "$y_n" == [Nn] ]]; then
			echo
			echo -e " $greenTelegram MTProto 끄기가 취소되었습니다....$none"
			echo
			break
		else
			error
		fi

	done
}
mtproto_port_config() {
	local random=$(shuf -i20001-65535 -n1)
	echo
	while :; do
		echo -e " "$yellow"Telegram MTProto"$none" 포트를 입력하세요 ["$magenta"1-65535"$none"]，"$yellow"V2Ray"$none" 포트와 같으면 안됩니다."
		read -p "$(echo -e "(기본 포트: ${cyan}${random}$none):") " new_mtproto_port
		[ -z "$new_mtproto_port" ] && new_mtproto_port=$random
		case $new_mtproto_port in
		$v2ray_port)
			echo
			echo " V2Ray 포트와 동일하면 안됩니다...."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $v2ray_transport == [45] ]]; then
				local tls=ture
			fi
			if [[ $tls && $new_mtproto_port == "80" ]] || [[ $tls && $new_mtproto_port == "443" ]]; then
				echo
				echo -e " "$green"WebSocket + TLS $none또는$green HTTP/2"$none" 프로토콜을 선택하였으므로"
				echo
				echo -e " "$magenta"80"$none" 또는 "$magenta"443"$none" 포트는 사용할 수 없습니다."
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start == $new_mtproto_port || $v2ray_dynamicPort_end == $new_mtproto_port ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 V2Ray 동적포트와 충돌합니다. 기존 V2Ray 동적 포트 범위 : ${cyan}$port_range${none}"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start -lt $new_mtproto_port && $new_mtproto_port -le $v2ray_dynamicPort_end ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 V2Ray 동적포트와 충돌합니다. 기존 V2Ray 동적 포트 범위 : ${cyan}$port_range${none}"
				error
			elif [[ $shadowsocks && $new_mtproto_port == $ssport ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 Shadowsocks 포트와 충돌합니다. 기존 Shadowsocks 포트 : ${cyan}$ssport$none"
				error
			elif [[ $socks && $new_mtproto_port == $socks_port ]]; then
				echo
				echo -e "죄송합니다. 선택하신 포트는 Socks 포트와 충돌합니다. 기존 Socks 포트: ${cyan}$socks_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow Telegram MTProto 포트 = $cyan$new_mtproto_port$none"
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
change_mtproto_secret() {
	new_mtproto_secret="dd$(date | md5sum | cut -c-30)"
	echo
	while :; do
		read -p "$(echo -e " ${yellow}Telegram MTProto 키${none}를 변경하시겠습니까? [${magenta}Y/N$none]"): " y_n
		[ -z "$y_n" ] && error && continue
		case $y_n in
		n | N)
			echo
			echo -e " 변경이 취소되었습니다.... "
			echo
			break
			;;
		y | Y)
			echo
			echo
			echo -e "$yellow Telegram MTProto 키 변경 = $cyan예$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config mtproto_secret
			mtproto_secret=$new_mtproto_secret
			config
			clear
			_mtproto_info
			break
			;;
		esac
	done
}
change_mtproto_port() {
	echo
	while :; do
		echo -e " "$yellow"Telegram MTProto"$none" 의 새로운 포트를 입력하세요 ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(기존 포트번호: ${cyan}${mtproto_port}$none):") " new_mtproto_port
		[ -z "$new_mtproto_port" ] && error && continue
		case $new_mtproto_port in
		$mtproto_port)
			echo
			echo " 기존 번호와 동일하면 안됩니다...."
			error
			;;
		$v2ray_port)
			echo
			echo " V2Ray 포트와 동일하면 안됩니다...."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $v2ray_transport == [45] ]]; then
				local tls=ture
			fi
			if [[ $tls && $new_mtproto_port == "80" ]] || [[ $tls && $new_mtproto_port == "443" ]]; then
				echo
				echo -e " "$green"WebSocket + TLS $none또는$green HTTP/2"$none" 프로토콜을 선택하였으므로"
				echo
				echo -e " "$magenta"80"$none" 또는 "$magenta"443"$none" 포트는 사용할 수 없습니다."
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start == $new_mtproto_port || $v2ray_dynamicPort_end == $new_mtproto_port ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 V2Ray 동적 포트와 충돌합니다. 기존 V2Ray 동적 포트 범위 : ${cyan}$port_range${none}"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start -lt $new_mtproto_port && $new_mtproto_port -le $v2ray_dynamicPort_end ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 V2Ray 동적 포트와 충돌합니다. 기존 V2Ray 동적 포트 범위 : ${cyan}$port_range${none}"
				error
			elif [[ $shadowsocks && $new_mtproto_port == $ssport ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 Shadowsocks 포트와 충돌합니다. 기존 Shadowsocks 포트: ${cyan}$ssport$none"
				error
			elif [[ $socks && $new_mtproto_port == $socks_port ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 Socks 포트와 충돌합니다. 기존 Socks 포트: ${cyan}$socks_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow socks 포트 = $cyan$new_mtproto_port$none"
				echo "----------------------------------------------------------------"
				echo
				pause
				backup_config mtproto_port
				mtproto_port=$new_mtproto_port
				config
				clear
				_mtproto_info
				break
			fi
			;;
		*)
			error
			;;
		esac

	done

}
