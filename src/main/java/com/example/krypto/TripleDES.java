package com.example.krypto;

import java.util.Arrays;

public class TripleDES {
    public byte[] encryptMessage(byte[] bytesOfContent,byte[] initialKey) {
        byte[]firstKey = Arrays.copyOfRange(initialKey,0,8);
        byte[]secondKey = Arrays.copyOfRange(initialKey,8,16);
        byte[]thirdKey = Arrays.copyOfRange(initialKey,16,24);
        DES des = new DES();
        byte[] correctSizeBlocks;
        if (bytesOfContent.length % 8 ==0) {
            correctSizeBlocks = Arrays.copyOf(bytesOfContent,bytesOfContent.length);
        } else {
            correctSizeBlocks = Arrays.copyOf(bytesOfContent,bytesOfContent.length + 8 - bytesOfContent.length % 8);
        }
        byte[] firstRound = des.encryptMessage(correctSizeBlocks,firstKey);
        byte[] secondRound = des.decryptMessage(firstRound,secondKey);
        byte[] thirdRound = des.encryptMessage(secondRound,thirdKey);
        return thirdRound;
    }
    public byte[] decryptMessage(byte[] bytesOfContent,byte[] initialKey) {
        byte[]firstKey = Arrays.copyOfRange(initialKey,0,8);
        byte[]secondKey = Arrays.copyOfRange(initialKey,8,16);
        byte[]thirdKey = Arrays.copyOfRange(initialKey,16,24);
        DES des = new DES();
        byte[] correctSizeBlocks;
        if (bytesOfContent.length % 8 ==0) {
            correctSizeBlocks = Arrays.copyOf(bytesOfContent,bytesOfContent.length);
        } else {
            correctSizeBlocks = Arrays.copyOf(bytesOfContent,bytesOfContent.length + 8 - bytesOfContent.length % 8);
        }
        byte[] firstRound = des.decryptMessage(correctSizeBlocks,thirdKey);
        byte[] secondRound = des.encryptMessage(firstRound,secondKey);
        byte[] thirdRound = des.decryptMessage(secondRound,firstKey);
        return thirdRound;
    }
}
