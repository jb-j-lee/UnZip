/*
 *  Copyright 2011, 2012 Martin Matula (martin@alutam.com)
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.github.myjb.unzip.compress;


import io.github.myjb.unzip.compress.ZipUtil.Section;
import io.github.myjb.unzip.compress.ZipUtil.State;

import java.io.IOException;
import java.io.InputStream;


/**
 * Traditional PKWARE Encryption
 * https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
 * 
 * Input stream converting a password-protected zip to an unprotected zip.
 *
 * <h3>Example usage:</h3>
 * <p>Reading a password-protected zip from file:</p>
 * <pre>
 *  ZipDecryptInputStream zdis = new ZipDecryptInputStream(new FileInputStream(fileName), password);
 *  ZipInputStream zis = new ZipInputStream(zdis);
 *  ... read the zip file from zis - the standard JDK ZipInputStream ...
 * </pre>
 * <p>Converting a password-protected zip file to an unprotected zip file:</p>
 * <pre>
 *  ZipDecryptInputStream src = new ZipDecryptInputStream(new FileInputStream(srcFile), password);
 *  FileOutputStream dest = new FileOutputStream(destFile);
 *
 *  // should wrap with try-catch-finally, do the close in finally
 *  int b;
 *  while ((b = src.read()) > -1) {
 *      dest.write(b);
 *  }
 *
 *  src.close();
 *  dest.close();
 * </pre>
 *
 * @author Martin Matula (martin at alutam.com)
 */
public class ZipDecryptInputStream extends InputStream {
    private final InputStream delegate;
    private final int keys[] = new int[3];
    private final int pwdKeys[] = new int[3];

    private State state = State.SIGNATURE;
    private boolean isEncrypted;
    private Section section;
    private int skipBytes;
    private int compressedSize;
    private int crc;

    private int fileNameLenth;
    private int[] fileName;
    private int extraFieldLenth;
    private byte[] rawName;

    /**
     * Creates a new instance of the stream.
     *
     * @param stream Input stream serving the password-protected zip file to be decrypted.
     * @param password Password to be used to decrypt the password-protected zip file.
     */
    public ZipDecryptInputStream(InputStream stream, String password, byte[] rawName) {
        this(stream, password.toCharArray());
        this.rawName = rawName;
    }

    /**
     * Safer constructor. Takes password as a char array that can be nulled right after
     * calling this constructor instead of a string that may be visible on the heap for
     * the duration of application run time.
     *
     * @param stream Input stream serving the password-protected zip file.
     * @param password Password to use for decrypting the zip file.
     */
    public ZipDecryptInputStream(InputStream stream, char[] password) {
        this.delegate = stream;
        pwdKeys[0] = 305419896;
        pwdKeys[1] = 591751049;
        pwdKeys[2] = 878082192;
        for (int i = 0; i < password.length; i++) {
            ZipUtil.updateKeys((byte) (password[i] & 0xff), pwdKeys);
        }
    }

    @Override
    public int read() throws IOException {
        int result = delegateRead();
        if (skipBytes == 0) {
            switch (state) {
                case SIGNATURE:
                    if (!peekAheadEquals(ZipUtil.LFH_SIGNATURE)) {
                        state = State.TAIL;
                    } else {
                        section = Section.FILE_HEADER;
                        skipBytes = 5;
                        state = State.FLAGS;
                    }
                    break;
//                case VERSION:
//                    skipBytes = 1;
//                    state = State.FLAGS;
//                    break;
                case FLAGS:
                    isEncrypted = (result & 1) != 0;
                    if ((result & 64) == 64) {
                        throw new IllegalStateException("Strong encryption used.");
                    }
                    if ((result & 8) == 8) {
                        compressedSize = -1;
                        state = State.FILE_NAME_LENGTH;
                        skipBytes = 19;
                    } else {
                    	if (isEncrypted) {
                    		state = State.CRC;
                    		skipBytes = 7;
                    	} else {
                    		state = State.COMPRESSION_METHOD;
                    		skipBytes = 1;
                    	}
                    }
                    if (isEncrypted) {
                        result -= 1;
                    }
                    break;
                case COMPRESSION_METHOD:
                    skipBytes = 5;
                    state = State.CRC;
                    break;
                case CRC:
                    int[] values = new int[4];
                    peekAhead(values);
                    crc = 0;
                    int valueInc = isEncrypted ? ZipUtil.DECRYPT_HEADER_SIZE : 0;
                    for (int i = 0; i < 4; i++) {
                    	crc += values[i] << (8 * i);
                    	values[i] -= valueInc;
                    	if(values[i] < 0) {
                    		valueInc = 1;
                    		values[i] += 256;
                    	} else {
                    		valueInc = 0;
                    	}
                    }
                    overrideBuffer(values);
                    result = values[0];
                    crc = values[3];
                    skipBytes = 3;
                    state = State.COMPRESSED_SIZE;
                    break;
                case COMPRESSED_SIZE:
                    values = new int[4];
                    peekAhead(values);
                    compressedSize = 0;
                    valueInc = isEncrypted ? ZipUtil.DECRYPT_HEADER_SIZE : 0;
                    for (int i = 0; i < 4; i++) {
                        compressedSize += values[i] << (8 * i);
                        values[i] -= valueInc;
                        if (values[i] < 0) {
                            valueInc = 1;
                            values[i] += 256;
                        } else {
                            valueInc = 0;
                        }
                    }
                    overrideBuffer(values);
                    result = values[0];
                    if (section == Section.DATA_DESCRIPTOR) {
                        state = State.SIGNATURE;
                    } else {
                        state = State.FILE_NAME_LENGTH;
                    }
                    skipBytes = 7;
                    break;
                case FILE_NAME_LENGTH:
                    values = new int[2];
                    peekAhead(values);
                    fileNameLenth = values[0] + values[1] * 256;
                    fileName = new int[fileNameLenth];
                    skipBytes = 1;
                    state = State.EXTRA_FIELD_LENGTH;
                    break;
                case EXTRA_FIELD_LENGTH:
                    values = new int[2];
                    peekAhead(values);
                    extraFieldLenth = values[0] + values[1] * 256;
                    if (!isEncrypted) {
                        if (compressedSize > 0) {
                        	state = State.HEADER;
//                        	throw new IllegalStateException("ZIP not password protected.");
                        }
                        else
                        	state = State.SIGNATURE;
                        skipBytes = 1 + fileNameLenth + extraFieldLenth;
                    } else {
                        state = State.FILE_NAME;
                        skipBytes = 1;
                    }
                    break;
                case FILE_NAME:
                    values = new int[BUF_SIZE];
                    peekAhead(values);
                    int fileNameOffset = 0;
                    int remain = 0;
                    if (fileNameLenth <= BUF_SIZE) {
                    	for (int i = 0; i < fileNameLenth; i++)
                    		fileName[fileNameOffset++] = values[i];
                    } else {
                    	for (int i = 0; i < BUF_SIZE; i++) {
                    		fileName[fileNameOffset++] = values[i];
                    		remain = i;
                    		if (fileNameOffset == fileNameLenth)
                    			break;
                    	}
                    }

                    if (fileNameLenth <= BUF_SIZE) {
                    	state = State.HEADER;
                    	skipBytes = (fileNameLenth - 1) + extraFieldLenth;
                    } else if (fileNameOffset == fileNameLenth) {
                    	state = State.HEADER;
                    	skipBytes = remain + extraFieldLenth;
                    } else {
                    	state = State.FILE_NAME;
                    	skipBytes = BUF_SIZE - 1;
                    }
                    break;
                case HEADER:
                    section = Section.FILE_DATA;
                    if (isEncrypted) {
                    	initKeys();
                    	byte lastValue = 0;
                    	for (int i = 0; i < ZipUtil.DECRYPT_HEADER_SIZE; i++) {
                            lastValue = (byte) (result ^ decryptByte());
                            updateKeys(lastValue);
                            result = delegateRead();
                        }

                    	if ((lastValue & 0xff) != crc) {
                    		if (fileNameLenth == rawName.length) {
                    			boolean checksum = true;
                    			for (int i = 0; i < fileNameLenth; i++) {
                    				if( (byte)fileName[i] != rawName[i]) {
                    					checksum = false;
                    					break;
                    				}
                    			}
                    			
                    			if (checksum)
                    				throw new IllegalStateException("Wrong password!");
                    		}
                    	}
                    	compressedSize -= ZipUtil.DECRYPT_HEADER_SIZE;
                    }
                    
                    state = State.DATA;
                    // intentionally no break
                case DATA:
                	if (isEncrypted) {
                		if (compressedSize == -1 && peekAheadEquals(ZipUtil.DD_SIGNATURE)) {
                			section = Section.DATA_DESCRIPTOR;
                			skipBytes = 2;
                			state = State.CRC;
                		} else {
                			result = (result ^ decryptByte()) & 0xff;
                			updateKeys((byte) result);
                			compressedSize--;
                			if (compressedSize == 0) {
                				state = State.SIGNATURE;
                			}
                		}
                	} else {
                		compressedSize--;
                		if (compressedSize == 0) {
                			state = State.SIGNATURE;
                		}
                	}
                    break;
                case TAIL:
                    // do nothing
            }
        } else {
            skipBytes--;
        }
        return result;
    }

    private static final int BUF_SIZE = 8;
    private int bufOffset = BUF_SIZE;
    private final int[] buf = new int[BUF_SIZE];

    private int delegateRead() throws IOException {
        bufOffset++;
        if (bufOffset >= BUF_SIZE) {
            fetchData(0);
            bufOffset = 0;
        }
        return buf[bufOffset];
    }

    private boolean peekAheadEquals(int[] values) throws IOException {
        prepareBuffer(values);
        for (int i = 0; i < values.length; i++) {
            if (buf[bufOffset + i] != values[i]) {
                return false;
            }
        }
        return true;
    }

    private void prepareBuffer(int[] values) throws IOException {
        if (values.length > (BUF_SIZE - bufOffset)) {
            for (int i = bufOffset; i < BUF_SIZE; i++) {
                buf[i - bufOffset] = buf[i];
            }
            fetchData(BUF_SIZE - bufOffset);
            bufOffset = 0;
        }
    }

    private void peekAhead(int[] values) throws IOException {
        prepareBuffer(values);
        System.arraycopy(buf, bufOffset, values, 0, values.length);
    }

    private void overrideBuffer(int[] values) throws IOException {
        prepareBuffer(values);
        System.arraycopy(values, 0, buf, bufOffset, values.length);
    }

    private void fetchData(int offset) throws IOException {
        for (int i = offset; i < BUF_SIZE; i++) {
            buf[i] = delegate.read();
            if (buf[i] == -1) {
                break;
            }
        }
    }

    @Override
    public void close() throws IOException {
        delegate.close();
        super.close();
    }

    private void initKeys() {
        System.arraycopy(pwdKeys, 0, keys, 0, keys.length);
    }

    private void updateKeys(byte charAt) {
        ZipUtil.updateKeys(charAt, keys);
    }

    private byte decryptByte() {
        int temp = keys[2] | 2;
        return (byte) ((temp * (temp ^ 1)) >>> 8);
    }
}
