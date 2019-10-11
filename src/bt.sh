_ban_bt_main() {
	if [[ $ban_bt ]]; then
		local _info="$green켬$none"
	else
		local _info="$red끔$none"
	fi
	_opt=''
	while :; do
		echo
		echo -e "$yellow 1. $noneBT 차단 켜기"
		echo
		echo -e "$yellow 2. $noneBT 차단 끄기"
		echo
		echo -e "기존 BT 차단 상태: $_info"
		echo
		read -p "$(echo -e "선택해주세요 [${magenta}1-2$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				if [[ $ban_bt ]]; then
					echo
					echo -e " 기존 BT 차단 상태: $_info) 입니다.....다시 켤 필요 없습니다."
					echo
				else
					echo
					echo
					echo -e "$yellow  BT 차단 = $cyan켬$none"
					echo "----------------------------------------------------------------"
					echo
					pause
					backup_config +bt
					ban_bt=true
					config
					echo
					echo
					echo -e "$green  BT 차단이 시작되었습니다...에러가 발생하면, 이 기능을 꺼주세요.$none"
					echo
				fi
				break
				;;
			2)
				if [[ $ban_bt ]]; then
					echo
					echo
					echo -e "$yellow  BT 차단 = $cyan끔$none"
					echo "----------------------------------------------------------------"
					echo
					pause
					backup_config -bt
					ban_bt=''
					config
					echo
					echo
					echo -e "$red  BT 차단이 꺼졌습니다...원하시면 다시 켜실 수 있습니다.$none"
					echo
				else
					echo
					echo -e " 기존 BT 차단 상태: $_info) 입니다.....다시 끌 필요 없습니다."
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
