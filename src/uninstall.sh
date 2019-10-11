while :; do
	echo
	read -p "$(echo -e " ${yellow}V2Ray$none를 제거하시겠습니까? [${magenta}Y/N$none]:")" uninstall_v2ray_ask
	if [[ -z $uninstall_v2ray_ask ]]; then
		error
	else
		case $uninstall_v2ray_ask in
		Y | y)
			is_uninstall_v2ray=true
			echo
			echo -e "$yellow V2Ray 제거 = ${cyan}예${none}"
			echo
			break
			;;
		N | n)
			echo
			echo -e "$red 제거가 취소되었습니다...$none"
			echo
			break
			;;
		*)
			error
			;;
		esac
	fi
done

if [[ $caddy && $is_uninstall_v2ray ]] && [[ -f /usr/local/bin/caddy && -f /etc/caddy/Caddyfile ]]; then
	while :; do
		echo
		read -p "$(echo -e " ${yellow}Caddy$none를 제거하시겠습니까? [${magenta}Y/N$none]:")" uninstall_caddy_ask
		if [[ -z $uninstall_caddy_ask ]]; then
			error
		else
			case $uninstall_caddy_ask in
			Y | y)
				is_uninstall_caddy=true
				echo
				echo -e "$yellow Caddy 제거 = ${cyan}예${none}"
				echo
				break
				;;
			N | n)
				echo
				echo -e "$yellow Caddy 제거 = ${cyan}아니오${none}"
				echo
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
fi

if [[ $is_uninstall_v2ray && $is_uninstall_caddy ]]; then
	pause
	echo

	if [[ $shadowsocks ]]; then
		del_port $ssport
	fi
	if [[ $socks ]]; then
		del_port $socks_port
	fi
	if [[ $mtproto ]]; then
		del_port $mtproto_port
	fi

	if [[ $v2ray_transport == [45] ]]; then
		del_port "80"
		del_port "443"
		del_port $v2ray_port
	elif [[ $v2ray_transport -ge 18 ]]; then
		del_port $v2ray_port
		del_port "multiport"
	else
		del_port $v2ray_port
	fi

	[ $cmd == "apt-get" ] && rm -rf /etc/network/if-pre-up.d/iptables

	# [ $v2ray_pid ] && systemctl stop v2ray
	[ $v2ray_pid ] && do_service stop v2ray

	rm -rf /usr/bin/v2ray
	rm -rf $_v2ray_sh
	sed -i '/alias v2ray=/d' /root/.bashrc
	rm -rf /etc/v2ray
	rm -rf /var/log/v2ray

	# [ $caddy_pid ] && systemctl stop caddy
	[ $caddy_pid ] && do_service stop caddy

	rm -rf /usr/local/bin/caddy
	rm -rf /etc/caddy
	rm -rf /etc/ssl/caddy

	if [[ $systemd ]]; then
		systemctl disable v2ray >/dev/null 2>&1
		rm -rf /lib/systemd/system/v2ray.service
		systemctl disable caddy >/dev/null 2>&1
		rm -rf /lib/systemd/system/caddy.service
	else
		update-rc.d -f caddy remove >/dev/null 2>&1
		update-rc.d -f v2ray remove >/dev/null 2>&1
		rm -rf /etc/init.d/caddy
		rm -rf /etc/init.d/v2ray
	fi
	# clear
	echo
	echo -e "$green V2Ray 제거가 완료되었습니다 ....$none"
	echo
	echo "만약 스크립트 사용에 불편한 점이 있으면 알려주세요."
	echo
	echo "문제점 보고: https://github.com/233boy/v2ray/issues"
	echo

elif [[ $is_uninstall_v2ray ]]; then
	pause
	echo

	if [[ $shadowsocks ]]; then
		del_port $ssport
	fi
	if [[ $socks ]]; then
		del_port $socks_port
	fi
	if [[ $mtproto ]]; then
		del_port $mtproto_port
	fi

	if [[ $v2ray_transport == [45] ]]; then
		del_port "80"
		del_port "443"
		del_port $v2ray_port
	elif [[ $v2ray_transport -ge 18 ]]; then
		del_port $v2ray_port
		del_port "multiport"
	else
		del_port $v2ray_port
	fi

	[ $cmd == "apt-get" ] && rm -rf /etc/network/if-pre-up.d/iptables

	# [ $v2ray_pid ] && systemctl stop v2ray
	[ $v2ray_pid ] && do_service stop v2ray

	rm -rf /usr/bin/v2ray
	rm -rf $_v2ray_sh
	sed -i '/alias v2ray=/d' /root/.bashrc
	rm -rf /etc/v2ray
	rm -rf /var/log/v2ray
	if [[ $systemd ]]; then
		systemctl disable v2ray >/dev/null 2>&1
		rm -rf /lib/systemd/system/v2ray.service
	else
		update-rc.d -f v2ray remove >/dev/null 2>&1
		rm -rf /etc/init.d/v2ray
	fi
	# clear
	echo
	echo -e "$green V2Ray 제거가 완료되었습니다 ....$none"
	echo
	echo "만약 스크립트 사용에 불편한 점이 있으면 알려주세요."
	echo
	echo "문제점 보고: https://github.com/233boy/v2ray/issues"
	echo
fi
