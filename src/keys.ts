import {BindingKey} from '@loopback/context';
import {JWTAuthenticationService} from './services/JWT.authentication.service';

export namespace JWTAuthenticationBindings {
  export const SECRET = BindingKey.create<string>('JWT.authentication.secret');
  export const SERVICE = BindingKey.create<JWTAuthenticationService>(
    'JWT.authentication.service',
  );
}
