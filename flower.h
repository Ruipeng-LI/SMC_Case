
#define _Winder_FLOWER //此开关控制编译器是否使用花指令,注销此行，花指令无效
//花指令定义	
#ifndef _Winder_FLOWER
#define _FLOWER_XX0  _asm nop
#define _FLOWER_XX1  _asm nop
#define _FLOWER_XX2  _asm nop
#else
#define _FLOWER_XX0 \
		{\
			_asm jz  $+0xd  	/*本指令6 bytes len*/ \
			_asm jnz $+7 		/*本指令6 bytes len*/ \
			_asm _emit 0xe8 	/*本指令1 bytes len*/ \
			/*这里是要转移到的地址*/ \
		}	
#define _FLOWER_XX1 \
		{\
			_asm jz  $+0xd  /*本指令6 bytes len*/ \
			_asm jnz $+7  /*本指令6 bytes len*/ \
			_asm _emit 0xe8 /*本指令1 bytes len*/ \
			/*这里是要转移到的地址*/ \
		}
#define _FLOWER_XX2 \
		{\
			_asm jz  $+0xd /*本指令6 bytes len*/ \
			_asm jnz $+7  /*本指令6 bytes len*/ \
			_asm _emit 0xe8 /*本指令1 bytes len*/ \
			/*这里是要转移到的地址*/ \
		}

#define __FLOWER__XX3 \
{\
	_asm	pushad\
	_asm	cmp esi, esi\
	_asm	je label\
	_asm	_emit 0e8h\
	_asm	loop label\
	_asm	_emit 0e8h\
	_asm	label :\
}

#define __FLOWER_XX4 \
{\
	_asm	jmp $ + 6h \
	_asm	_emit 0e8h \
	_asm	jz labelXX4_1 \
	_asm	jnz labelXX4_1 \
	_asm	_emit 0e8h \
_asm	labelXX4_1 : \
	_asm	jmp $ + 6 \
	_asm	_emit 0e8h \
	_asm	jnz labelXX4_2 \
	_asm	jz labelXX4_2 \
	_asm	_emit 0e8h \
	_asm	_emit 0e8h \
_asm	labelXX4_2 : \
}

#define __FLOWER_XX5 \
{\
	_asm	jmp $ + 6h \
	_asm	_emit 0e8h \
	_asm	jz labelXX5_1 \
	_asm	jnz labelXX5_1 \
	_asm	_emit 0e8h \
_asm	labelXX5_1 : \
	_asm	jmp $ + 6 \
	_asm	_emit 0e8h \
	_asm	jnz labelXX5_2 \
	_asm	jz labelXX5_2 \
	_asm	_emit 0e8h \
	_asm	_emit 0e8h \
_asm	labelXX5_2 : \
}

#define __FLOWER_XX6 \
{\
    int m = 0x11223344;\
	_asm	xor ESP, m \
	_asm	cmp ESP, m \
	_asm	jmp $ + 7 \
	_asm	_emit 075h \
	_asm	_emit 074h \
	_asm	je labelXX6_1 \
	_asm	jne labelXX6_2 \
	_asm	je labelXX6_1 \
	_asm	_emit 08eh \
	_asm	jne labelXX6_1 \
_asm	labelXX6_1 : \
	_asm	_emit 08eh \
	_asm	nop \
	_asm	nop \
	_asm	nop \
	_asm	nop \
	_asm	_emit 08eh \
	_asm	nop \
	_asm	nop \
	_asm	nop \
	_asm	nop \
	_asm	nop \
	_asm	_emit 74h \
	_asm	_emit 08eh \
	_asm	_emit 08eh \
_asm	labelXX6_2 : \
	_asm	xor ESP, m \
}

#define __FLOWER_XX7 \
{\
    int m = 0x11223344;\
	_asm	xor ESP, m \
	_asm	cmp ESP, m \
	_asm	jmp $ + 7 \
	_asm	_emit 075h \
	_asm	_emit 074h \
	_asm	je labelXX7_1 \
	_asm	jne labelXX7_2 \
	_asm	je labelXX7_1 \
	_asm	_emit 08eh \
	_asm	jne labelXX7_1 \
_asm	labelXX7_1 : \
	_asm	_emit 08eh \
	_asm	nop \
	_asm	nop \
	_asm	nop \
	_asm	nop \
	_asm	_emit 08eh \
	_asm	nop \
	_asm	nop \
	_asm	nop \
	_asm	nop \
	_asm	nop \
	_asm	_emit 74h \
	_asm	_emit 08eh \
	_asm	_emit 08eh \
_asm	labelXX7_2 : \
	_asm	xor ESP, m \
}
#endif