_view_socks_info() {
	if [[ $socks ]]; then
		_socks_info
	else
		_socks_ask
	fi
}
_socks_info() {
	[[ -z $ip ]] && get_ip
	echo
	echo "---------- Socks 설정정보 -------------"
	echo
	echo -e "$yellow 서버 (Hostname) = $cyan${ip}$none"
	echo
	echo -e "$yellow 포트 (Port) = $cyan$socks_port$none"
	echo
	echo -e "$yellow 사용자명 (Username) = $cyan$socks_username$none"
	echo
	echo -e "$yellow 암호 (Password) = $cyan$socks_userpass$none"
	echo
	echo -e "$yellow Telegram 프록시 설정 링크 = ${cyan}tg://socks?server=${ip}&port=${socks_port}&user=${socks_username}&pass=${socks_userpass}$none"
	echo
}
_socks_main() {
	if [[ $socks ]]; then

		while :; do
			echo
			echo -e "$yellow 1. $none Socks 설정 정보 보기"
			echo
			echo -e "$yellow 2. $none Socks 포트 수정"
			echo
			echo -e "$yellow 3. $none Socks 사용자명 수정"
			echo
			echo -e "$yellow 4. $none Socks 암호 수정"
			echo
			echo -e "$yellow 5. $none Socks 중지"
			echo
			read -p "$(echo -e "선택해주세요 [${magenta}1-4$none]:")" _opt
			if [[ -z $_opt ]]; then
				error
			else
				case $_opt in
				1)
					_socks_info
					break
					;;
				2)
					change_socks_port_config
					break
					;;
				3)
					change_socks_user_config
					break
					;;
				4)
					change_socks_pass_config
					break
					;;
				5)
					disable_socks
					break
					;;
				*)
					error
					;;
				esac
			fi

		done
	else
		_socks_ask
	fi
}
_socks_ask() {
	echo
	echo
	echo -e " $redSocks $none를 설정하지 않았습니다...지금 설정 가능합니다. ^_^"
	echo
	echo

	while :; do
		echo -e "${yellow}Socks${none}를 설정하시겠습니까? [${magenta}Y/N$none]"
		read -p "$(echo -e "(기본값 [${cyan}N$none]):") " new_socks
		[[ -z "$new_socks" ]] && new_socks="n"
		if [[ "$new_socks" == [Yy] ]]; then
			echo
			socks=true
			socks_port_config
			socks_user_config
			socks_pass_config
			pause
			open_port $new_socks_port
			backup_config +socks
			socks_port=$new_socks_port
			socks_username=$new_socks_username
			socks_userpass=$new_socks_userpass
			config
			clear
			_socks_info
			break
		elif [[ "$new_socks" == [Nn] ]]; then
			echo
			echo -e " $green Socks 설정을 취소하였습니다....$none"
			echo
			break
		else
			error
		fi

	done
}
disable_socks() {
	echo

	while :; do
		echo -e "${yellow}Socks${none}를 중지하시겠습니까? [${magenta}Y/N$none]"
		read -p "$(echo -e "(기본값 [${cyan}N$none]):") " y_n
		[[ -z "$y_n" ]] && y_n="n"
		if [[ "$y_n" == [Yy] ]]; then
			echo
			echo
			echo -e "$yellow Socks 중지 = $cyan예$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config -socks
			del_port $socks_port
			socks=''
			config
			echo
			echo
			echo
			echo -e "$green Socks가 중지되었습니다... 필요하시면 Socks를 다시 켤 수 있습니다 ...只要你喜欢$none"
			echo
			break
		elif [[ "$y_n" == [Nn] ]]; then
			echo
			echo -e " $green Socks 중지를 취소하였습니다....$none"
			echo
			break
		else
			error
		fi

	done
}
socks_port_config() {
	local random=$(shuf -i20001-65535 -n1)
	echo
	while :; do
		echo -e " "$yellow"Socks"$none" 포트를 입력해주세요 ["$magenta"1-65535"$none"]，"$yellow"V2Ray"$none" 포트와 같은 포트는 사용할 수 없습니다."
		read -p "$(echo -e "(기본 포트: ${cyan}${random}$none):") " new_socks_port
		[ -z "$new_socks_port" ] && new_socks_port=$random
		case $new_socks_port in
		$v2ray_port)
			echo
			echo " V2Ray 포트와 같은 포트는 사용할 수 없습니다..."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $v2ray_transport == [45] ]]; then
				local tls=ture
			fi
			if [[ $tls && $new_socks_port == "80" ]] || [[ $tls && $new_socks_port == "443" ]]; then
				echo
				echo -e " "$green"WebSocket + TLS $none또는$green HTTP/2"$none" 프로토콜을 선택하였으므로"
				echo
				echo -e " "$magenta"80"$none" 또는 "$magenta"443"$none" 포트는 선택할 수 없습니다."
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start == $new_socks_port || $v2ray_dynamicPort_end == $new_socks_port ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 V2Ray 동적포트와 충돌합니다. 기존 V2Ray 동적포트 범위：${cyan}$port_range${none}"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start -lt $new_socks_port && $new_socks_port -le $v2ray_dynamicPort_end ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 V2Ray 동적포트와 충돌합니다. 기존 V2Ray 동적포트 범위：${cyan}$port_range${none}"
				error
			elif [[ $shadowsocks && $new_socks_port == $ssport ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 Shadowsocks 포트와 충돌합니다. 기존 Shadowsocks 포트: ${cyan}$ssport$none"
				error
			elif [[ $mtproto && $new_socks_port == $mtproto_port ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 MTProto 포트와 충돌합니다. 기존 MTProto 포트: ${cyan}$mtproto_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow Socks 포트 = $cyan$new_socks_port$none"
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
socks_user_config() {
	echo
	while :; do
		read -p "$(echo -e "$yellow사용자명$none을 입력해주세요...(기본 사용자명: ${cyan}233blog$none)"): " new_socks_username
		[ -z "$new_socks_username" ] && new_socks_username="233blog"
		case $new_socks_username in
		*[/$]* | *\&*)
			echo
			echo -e " 사용자명에는 $red / $none또는$red $ $none또는$red & $none의 3개 특수문자는 사용할 수 없습니다.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow 사용자명 = $cyan$new_socks_username$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done

}
socks_pass_config() {
	echo
	while :; do
		read -p "$(echo -e "$yellow암호$none를 입력하세요...(기본 암호: ${cyan}233blog.com$none)"): " new_socks_userpass
		[ -z "$new_socks_userpass" ] && new_socks_userpass="233blog.com"
		case $new_socks_userpass in
		*[/$]* | *\&*)
			echo
			echo -e " 암호에는 $red / $none또는$red $ $none또는$red & $none의 3개 특수문자는 사용할 수 없습니다..... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow 암호 = $cyan$new_socks_userpass$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done
}
change_socks_user_config() {
	echo
	while :; do
		read -p "$(echo -e "$yellow사용자명$none을 입력하세요...(기존 사용자명: ${cyan}$socks_username$none)"): " new_socks_username
		[ -z "$new_socks_username" ] && error && continue
		case $new_socks_username in
		$socks_username)
			echo
			echo -e " 기존 사용자명과 동일합니다."
			echo
			error
			;;
		*[/$]* | *\&*)
			echo
			echo -e " 사용자명에는 $red / $none또는$red $ $none또는$red & $none의 3개 특수문자는 사용할 수 없습니다.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow 사용자명 = $cyan$new_socks_username$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config socks_username
			socks_username=$new_socks_username
			config
			clear
			_socks_info
			break
			;;
		esac
	done
}
change_socks_pass_config() {
	echo
	while :; do
		read -p "$(echo -e "$yellow암호$none를 입력하세요...(기존 암호: ${cyan}$socks_userpass$none)"): " new_socks_userpass
		[ -z "$new_socks_userpass" ] && error && continue
		case $new_socks_userpass in
		$socks_userpass)
			echo
			echo -e " 기존 암호와 동일합니다.
			echo
			error
			;;
		*[/$]* | *\&*)
			echo
			echo -e " 암호에는 $red / $none또는$red $ $none또는$red & $none의 3개 특수문자는 사용할 수 없습니다.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow 암호 = $cyan$new_socks_userpass$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config socks_userpass
			socks_userpass=$new_socks_userpass
			config
			clear
			_socks_info
			break
			;;
		esac
	done
}
change_socks_port_config() {
	echo
	while :; do
		echo -e "새로운 $yellow"Socks"$none" 포트 번호를 입력하세요. ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(기존 포트번호: ${cyan}${socks_port}$none):") " new_socks_port
		[ -z "$new_socks_port" ] && error && continue
		case $new_socks_port in
		$socks_port)
			echo
			echo " 기존 포트 번호와 동일합니다...."
			error
			;;
		$v2ray_port)
			echo
			echo " V2Ray 포트와 동일한 포트는 사용할 수 없습니다...."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $v2ray_transport == [45] ]]; then
				local tls=ture
			fi
			if [[ $tls && $new_socks_port == "80" ]] || [[ $tls && $new_socks_port == "443" ]]; then
				echo
				echo -e " "$green"WebSocket + TLS $none또는$green HTTP/2"$none" 프로토콜을 선택하였으므로"
				echo
				echo -e " "$magenta"80"$none" 또는 "$magenta"443"$none" 포트는 선택할 수 없습니다."
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start == $new_socks_port || $v2ray_dynamicPort_end == $new_socks_port ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 V2Ray 동적포트와 충돌합니다. 기존 V2Ray 동적포트 범위：${cyan}$port_range${none}"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start -lt $new_socks_port && $new_socks_port -le $v2ray_dynamicPort_end ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 V2Ray 동적포트와 충돌합니다. 기존 V2Ray 동적포트 범위：${cyan}$port_range${none}"
				error
			elif [[ $shadowsocks && $new_socks_port == $ssport ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 Shadowsocks 포트와 충돌합니다. 기존 Shadowsocks 포트: ${cyan}$ssport$none"
				error
			elif [[ $mtproto && $new_socks_port == $mtproto_port ]]; then
				echo
				echo -e " 죄송합니다. 선택하신 포트는 MTProto 포트와 충돌합니다. 기존 MTProto 포트: ${cyan}$mtproto_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow socks 포트 = $cyan$new_socks_port$none"
				echo "----------------------------------------------------------------"
				echo
				pause
				backup_config socks_port
				socks_port=$new_socks_port
				config
				clear
				_socks_info
				break
			fi
			;;
		*)
			error
			;;
		esac

	done

}
