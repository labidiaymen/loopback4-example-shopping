// Copyright IBM Corp. 2018, 2019. All Rights Reserved.
// Node module: @loopback4-example-shopping
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import * as _ from 'lodash';
import {Credentials, UserRepository} from '../repositories/user.repository';
import {toJSON} from '@loopback/testlab';
import {promisify} from 'util';
import * as isemail from 'isemail';
import {HttpErrors} from '@loopback/rest';
import {UserProfile} from '@loopback/authentication';
import {inject, ValueOrPromise, Provider} from '@loopback/core';
import {repository} from '@loopback/repository';
const jwt = require('jsonwebtoken');
const signAsync = promisify(jwt.sign);
const verifyAsync = promisify(jwt.verify);

export class JWTAuthenticationService {
  constructor(
    public userRepository: UserRepository,
    protected jwt_secret: string,
  ) {}

  async getAccessTokenForUser(credentials: Credentials): Promise<string> {
    const foundUser = await this.userRepository.findOne({
      where: {email: credentials.email, password: credentials.password},
    });
    if (!foundUser) {
      throw new HttpErrors.Unauthorized('Wrong credentials!');
    }

    const currentUser = _.pick(toJSON(foundUser), ['id', 'email', 'firstName']);

    // Generate user token using JWT
    const token = await signAsync(currentUser, this.jwt_secret, {
      expiresIn: 300,
    });

    return token;
  }

  validateCredentials(credentials: Credentials) {
    // Validate Email
    if (!isemail.validate(credentials.email)) {
      throw new HttpErrors.UnprocessableEntity('invalid email');
    }

    // Validate Password Length
    if (credentials.password.length < 8) {
      throw new HttpErrors.UnprocessableEntity(
        'password must be minimum 8 characters',
      );
    }
  }

  async decodeAccessToken(token: string): Promise<UserProfile> {
    const decoded = await verifyAsync(token, this.jwt_secret);
    let user = _.pick(decoded, ['id', 'email', 'firstName']);
    (user as UserProfile).name = user.firstName;
    delete user.firstName;
    return user;
  }
}

// Error:
// A class can only implement an identifier/qualified-name with
// optional type arguments. [2500]

// Does service have to be a provider?
export class JWTAuthenticationServiceProvider
  implements Provider<JWTAuthenticationService>() {
  constructor(
    @repository(UserRepository) public userRepository: UserRepository,
    @inject('JWT.authentication.secret') protected jwt_secret: string,
  ) {}
  value(): ValueOrPromise<JWTAuthenticationService> {
    return new JWTAuthenticationService(this.userRepository, this.jwt_secret);
  }
}
