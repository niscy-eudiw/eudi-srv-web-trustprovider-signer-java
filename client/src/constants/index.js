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

export const ASSINA_RSSP_BASE_URL =
  process.env.REACT_APP_APP_BASE_URL || "http://localhost:8082";
export const ASSINA_SA_BASE_URL =
  process.env.REACT_APP_SA_BASE_URL || "http://localhost:8083";
export const ASSINA_CLIENT_BASE_URL =
    process.env.ASSINA_CLIENT_BASE_URL || "http://localhost:3000";

export const API_BASE_URL = ASSINA_RSSP_BASE_URL + "/api/v1";
export const CSC_BASE_URL = ASSINA_RSSP_BASE_URL + "/csc/v1";
export const SA_BASE_URL = ASSINA_SA_BASE_URL + "/sa";

console.log("API_BASE_URL:        " + API_BASE_URL);
console.log("CSC_BASE_URL:        " + CSC_BASE_URL);
console.log("ASSINA_SA_BASE_URL:  " + ASSINA_SA_BASE_URL);

export const ACCESS_TOKEN = "accessToken";
