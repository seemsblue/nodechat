// src/types/express/index.d.ts
import express from 'express';

declare global {
  namespace Express {
    interface User {
      id: string;
      username: string;
    }

    interface Request {
      logIn(user: User, done: (err: any) => void): void;
      logOut(): void;
      user?: User; // req.user를 사용할 수 있도록 설정
    }
  }
}

//isAuthenticated 추가 >> 로그인 확인 boolean
declare global {
  namespace Express {
      interface Request {
          isAuthenticated(): boolean;
      }
  }
}

//req.logout 추가
declare global {
  namespace Express {
      interface Request {
          isAuthenticated(): boolean;
          logOut(callback: (err?: Error) => void): void;
          logout(callback: (err?: Error) => void): void;  // logout 메서드 추가
      }
  }
}