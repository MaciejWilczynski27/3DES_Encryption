package com.example.krypto;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.BitSet;

public class DES {

  final byte[] pBlock = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};
  //P-Block (Permutation Block) to tablica zawierająca permutacje bitów bloku danych wejściowych przed kolejnymi
  // rundami szyfrowania w algorytmie DES. P-Block składa się z 32 elementów, z których każdy określa numer bitu w 64-bitowym bloku wejściowym.
  //S-Box - tablica która służy do przekształcania bloków wejściowych w bloki wyjściowe, kazdy element to 4 bitowa liczba
  final byte[] sBox = {
                  // S1
                  14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                  0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                  4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                  15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
                  // S2
                  15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                  3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                  0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                  13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
                  // S3
                  10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                  13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                  13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                  1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
                  // S4
                  7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                  13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                  10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                  3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
                  // S5
                  2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                  14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                  4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                  11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
                  // S6
                  12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                  10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                  9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                  4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
                  // S7
                  4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                  13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                  1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                  6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
                  // S8
                  13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                  1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                  7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                  2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
          };

    final byte[] initialPermutation = {
            58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
            57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
    };
    final byte[] finalPermutation = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41,  9, 49, 17, 57, 25 };

    final byte[] halfPermutation = {
            32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,
            12,13,12,13,14,15,16,17,16,17,18,19,
            20,21,20,21,22,23,24,25,24,25,26,27,
            28,29,28,29,30,31,32,1
    };



    public BitSet findPermutation(int row, int column,int sboxNumber) {
        byte[] permutation = new byte[1];

        int perm =0;
        perm = sBox[row*16 +(sboxNumber*64-64)+column];
        permutation[0] = (byte) perm;
        BitSet converted = convertToBitSet(permutation);

        return converted;
    }

    public BitSet shrinkAndPermuteBits(BitSet toShrink) {

        BitSet sixBits ;
        BitSet twoBits ;
        BitSet fourBits;
        BitSet shrinked;
        BitSet concatedAndShrinked = new BitSet();
        int sboxNumber = 0;
        int row = 0;
        int column = 0;
        for(int i=0;i<48;i+=6) {
            sboxNumber++;
            sixBits = new BitSet();
            twoBits = new BitSet();
            fourBits = new BitSet();
            shrinked = new BitSet();
            for(int j=0;j<6;j++) {
                sixBits.set(j,toShrink.get(j+i));
            }
            twoBits.set(6,sixBits.get(0));
            twoBits.set(7,sixBits.get(5));
            for(int z=0;z<4;z++) {
                fourBits.set(z+4,sixBits.get(z+1));
            }
            row = fixedBitSetToByte(twoBits,1)[0];
            column = fixedBitSetToByte(fourBits,1)[0];
            shrinked = findPermutation(row,column,sboxNumber);

            for (int k = 4; k < 8; k++) {
                concatedAndShrinked.set( i/6 *4 + k-4 ,shrinked.get(k));
            }
        }
        return concatedAndShrinked;
    }
    public byte[] encryptMessage(byte[] bytesOfContent,byte[] initialKey) {

        byte[][] subKeys = generateSubkeys(initialKey);
        byte [] mergedBlock;
        BitSet bitContent;
        BitSet left;
        BitSet right;
        BitSet subkey;
        BitSet bufferedRight;


        byte[] encryptedBytes = new byte[bytesOfContent.length];

      for (int i = 0; i < bytesOfContent.length / 8; i++) {
          byte[] block = Arrays.copyOfRange(bytesOfContent, i * 8, i * 8 + 8);
          bitContent = convertToBitSet(block);
          bitContent = permute(bitContent,initialPermutation,64);
          left = genLeftHalf(bitContent,32);
          right = genRightHalf(bitContent,32);
            for(int j=0;j < 16;j++) {
                bufferedRight = (BitSet) right.clone();
                right = permute(right,halfPermutation,48);
                subkey = convertToBitSet(subKeys[j]);
                right.xor(subkey);
                right = shrinkAndPermuteBits(right);
                right = permute(right,pBlock,32);
                right.xor(left);
                left = bufferedRight;

            }
            mergedBlock = fixedBitSetToByte(permute(mergeBitSets(right,left,32),finalPermutation,64),8);
            for (int j = 0; j < 8; j++) {
                encryptedBytes[i * 8 + j] = mergedBlock[j];
            }
      }

        return encryptedBytes;
    }


    public byte[][] generateSubkeys(byte[] initialKey) {

      byte[][] subKeys = new byte[16][];
      final byte[] SHIFTS = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

      final byte[] PC1 = {57, 49, 41, 33, 25, 17, 9, 1,
                          58, 50, 42, 34, 26, 18, 10, 2,
                          59, 51, 43, 35, 27, 19, 11, 3,
                          60, 52, 44, 36, 63, 55, 47, 39,
                          31, 23, 15, 7, 62, 54, 46, 38,
                          30, 22, 14, 6, 61, 53, 45, 37,
                          29, 21, 13, 5, 28, 20, 12, 4};

      final byte[] PC2 = {14, 17, 11, 24, 1, 5, 3, 28,
                          15, 6, 21, 10, 23, 19, 12, 4,
                          26, 8, 16, 7, 27, 20, 13, 2,
                          41, 52, 31, 37, 47, 55, 30, 40,
                          51, 45, 33, 48, 44, 49, 39, 56,
                          34, 53, 46, 42, 50, 36, 29, 32};



      // najpierw permutacja z PC1, potem left shift
      BitSet bs = convertToBitSet(initialKey);


      BitSet pc1Bits = permute(bs,PC1,56);


      BitSet leftHalf = genLeftHalf(pc1Bits,28);
      BitSet rightHalf = genRightHalf(pc1Bits,28);
      BitSet mergedKey;
      BitSet afterPerm;
      BitSet testSet = new BitSet();

      for (int i = 0; i < 16; i++) {
          for (int j = 0; j < SHIFTS[i]; j++) {
            leftHalf = shiftBits(leftHalf,27,28);
              rightHalf = shiftBits(rightHalf,27,28);
          }
          mergedKey = mergeBitSets(leftHalf,rightHalf,28);
          afterPerm = permute(mergedKey,PC2,48);
          testSet = null;
          subKeys[i] = fixedBitSetToByte(afterPerm,6);
          testSet = convertToBitSet(subKeys[i]);
      }
      return subKeys;
    }
    public byte[] decryptMessage(byte[] bytesOfContent,byte[] initialKey) {

        byte[][] subKeys = generateSubkeys(initialKey);
        byte [] mergedBlock;
        BitSet bitContent;
        BitSet left;
        BitSet right;
        BitSet subkey;
        BitSet bufferedRight;


        byte[] decryptedBytes = new byte[bytesOfContent.length];

        for (int i = 0; i < bytesOfContent.length / 8; i++) {
            byte[] block = Arrays.copyOfRange(bytesOfContent, i * 8, i * 8 + 8);
            bitContent = convertToBitSet(block);
            bitContent = permute(bitContent,initialPermutation,64);
            left = genLeftHalf(bitContent,32);
            right = genRightHalf(bitContent,32);
            for(int j=0;j < 16;j++) {
                bufferedRight = (BitSet) right.clone();
                right = permute(right,halfPermutation,48);
                subkey = convertToBitSet(subKeys[15-j]);
                right.xor(subkey);
                right = shrinkAndPermuteBits(right);
                right = permute(right,pBlock,32);
                right.xor(left);
                left = bufferedRight;

            }
            mergedBlock = fixedBitSetToByte(permute(mergeBitSets(right,left,32),finalPermutation,64),8);
            for (int j = 0; j < 8; j++) {
                decryptedBytes[i * 8 + j] = mergedBlock[j];
            }
        }

        return decryptedBytes;
    }

    public BitSet mergeBitSets(BitSet leftSet, BitSet rightSet,int halfSize) {
        BitSet merged = new BitSet(halfSize*2);
        for(int i = 0;i < halfSize;i++) {
            merged.set(i, leftSet.get(i));
            merged.set(i + halfSize,rightSet.get(i));
        }
        return merged;
    }

    public byte[] fixedBitSetToByte(BitSet bitSet, int byteArraySize) {
        byte[] bytes = new byte[byteArraySize];
        StringBuilder stringBuilder = new StringBuilder();
        for(int g=0;g<8*byteArraySize;g++) {
            if(bitSet.get(g)) {
                stringBuilder.append('1');
            } else {
                stringBuilder.append('0');
            }
        }
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(stringBuilder.toString().substring(8 * i, 8 * (i + 1)), 2);
        }
        return bytes;
    }

    public BitSet shiftBits(BitSet toShift,int lastBitIndex,int size) {
        boolean leftElement = toShift.get(0);
        for (int i = 1; i < size; i++) {
            toShift.set(i-1,toShift.get(i));
        }
        toShift.set(lastBitIndex,leftElement);
        return toShift;
    }
    public BitSet permute(BitSet bs,byte[] permArray,int amountOfBits) {
        BitSet pc1Bits = new BitSet();
        for (int j = 0; j < amountOfBits; j++) {
            pc1Bits.set(j,bs.get(permArray[j]-1));
        }
        return pc1Bits;
    }
    public BitSet genLeftHalf(BitSet initial,int halfSize) {
        BitSet left = new BitSet(halfSize);
        for (int i = 0; i < halfSize; i++) {
            left.set(i, initial.get(i));
        }
        return left;
    }

    public BitSet genRightHalf(BitSet initial,int halfSize) {
        BitSet right = new BitSet(halfSize);
        for(int i=0;i<halfSize;i++) {
            right.set(i,initial.get(i+halfSize));
        }
        return right;
    }
    public BitSet convertToBitSet(byte[] array) {
        BitSet bitSet = new BitSet();
        for (int i = 0; i < array.length;i++) {
            String binary = String.format("%8s",Integer.toBinaryString(array[i] & 0xFF)).replace(' ','0');
            for (int j = 0; j < 8;j++) {
                if(binary.charAt(j) == '1'){
                    bitSet.set(i*8+j,true);
                } else{
                    bitSet.set(i*8+j,false);

                }
            }
        }
        return bitSet;
    }

}