#ifndef KRYPTO_H
#define KRYPTO_H

#include <iostream>
#include <QDebug>
#include <QRandomGenerator>
#include <QtMath>
using namespace std;
void gcd(qint64, qint64, qint64 *);
qint64 GCD_two(qint64 a,qint64 b);
qint64 exp_mod(qint64, qint64, qint64 );
bool is_prime_number(qint64 );
qint64 big_baby_step(qint64, qint64, qint64);
void gen_CxDx(QVector<qint64> &cxbx, qint64 p);
qint64 shamir_coding(qint64 msg, qint64 ca, qint64 p);
qint64 shamir_decoding(qint64 msg_code,qint64 cb, qint64 da, qint64 db, qint64 p);
qint64 gen_prime_num(qint64 min, qint64 max);
#endif // KRYPTO_H
