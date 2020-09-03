/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

\! echo "Configuring MySQL users...";

/*
Aries
*/
CREATE USER 'aries'@'%' IDENTIFIED BY 'aries-secret-pw';
GRANT ALL PRIVILEGES ON * . * TO 'aries'@'%';
