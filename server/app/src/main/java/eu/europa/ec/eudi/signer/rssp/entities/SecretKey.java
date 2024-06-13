/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.rssp.entities;

import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "secret_key")
public class SecretKey {
    @Id
    private String id;

    @Column(nullable = true, length = 2000)
    private byte[] secretKey;

    public SecretKey() {
        this.id = UUID.randomUUID().toString();
    }

    public SecretKey(byte[] sk) {
        this.id = UUID.randomUUID().toString();
        this.secretKey = sk;
    }

    public byte[] getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(byte[] sk) {
        this.secretKey = sk;
    }
}
