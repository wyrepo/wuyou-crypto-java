package com.wuyou.crypto.sm.sm4;

public enum SM4Mode {

    SM4_ECB_NoPadding("SM4/ECB/NoPadding"),
    SM4_ECB_PKCS5Padding("SM4/ECB/PKCS5Padding"),
    SM4_ECB_PKCS7Padding("SM4/ECB/PKCS7Padding"),
    SM4_CBC_NoPadding("SM4/CBC/NoPadding"),
    SM4_CBC_PKCS5Padding("SM4/CBC/PKCS5Padding"),
    SM4_CBC_PKCS7Padding("SM4/CBC/PKCS7Padding");

    private String name;

    SM4Mode(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

}
