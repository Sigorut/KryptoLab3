#include "krypto.h"

qint64 GCD_two(qint64 a,qint64 b) {
  return b?GCD_two(b,a%b):a;
}
qint64 gen_prime_num(qint64 min, qint64 max){
    qint64 i = QRandomGenerator::global()->bounded((int)min, (int)max);
    for(; i > 1; i-- )
        if(is_prime_number(i)){
            return i;
        }

    return -1;
}
void gcd(qint64 first, qint64 second, qint64 gcdFS_x_y[])
{
    if(first < second){
        qSwap(first,second);
    }
    qint64 q, v[3] = {second, 0, 1}, t[3];
    gcdFS_x_y[0] = first;
    gcdFS_x_y[1] = 1;
    gcdFS_x_y[2] = 0;
    while (v[0] != 0)
    {
        q = gcdFS_x_y[0] / v[0];
        t[0] = gcdFS_x_y[0] % v[0];
        t[1] = gcdFS_x_y[1] - q * v[1];
        t[2] = gcdFS_x_y[2] - q * v[2];
        for (qint64 i = 0; i < 3; i++)
        {
            gcdFS_x_y[i] = v[i];
            v[i] = t[i];
        }
    }
    if (gcdFS_x_y[2] < 0){
        gcdFS_x_y[2]+=first;
    }
}

qint64 exp_mod(qint64 a, qint64 x, qint64 p)
{
    qint64 x_one_bin, answer = 1;
    while(x > 0)
    {
        x_one_bin = x & 1;
        x = x>>1;
        if(x_one_bin == 1)
        {
            answer = answer * a % p;
        }
        a = a * a % p;
    }
    return answer;
}
bool is_prime_number(qint64 number)
{
    if (number <= 1) {
        return false;
    }
    qint64 v = 2;
    while (v * v <= number) {
        if (number % v++ == 0) return false;
    };
    return true;
}

bool check_equal_num(QVector<qint64> first, QVector<qint64> second, qint64 *first_index, qint64 *second_index){
    for(qint64 i = 0; i < first.size(); i++){
        for(qint64 j = 0; j < second.size(); j++){
            if(first[i] == second[j]){
                *first_index = i+1;
                *second_index = j+1;
                return true;
            }
        }
    }
    return false;
}

qint64 big_baby_step(qint64 a, qint64 p, qint64 y){
    qint64 m = 0, k=0;
    m = (qint64)qRound(qSqrt(p))+1;
    k = m;
    QVector<qint64> m_row, k_row;
    qint64 m_row_num = 0, k_row_num = 0, count = 1;
    qDebug() << "m =  " << m << " k = " << k;
    while(1){
        if(count-1 < m-1)
            m_row.push_back((exp_mod(a,count,p)*y%p)%p);
        if(check_equal_num(m_row, k_row, &m_row_num, &k_row_num)){
            qDebug() << m_row << k_row;
             qDebug() << m_row_num << k_row_num;
            break;
        }
        if(count < k)
            k_row.push_back(exp_mod(a,(count)*m,p));
        if(check_equal_num(m_row, k_row, &m_row_num, &k_row_num)){
            qDebug() << m_row << k_row;
            qDebug() << m_row_num << k_row_num;
            break;
        }
        count++;
    }
    return ((k_row_num * m) - m_row_num);
}

qint64 shamir_coding(qint64 msg, qint64 ca, qint64 p)
{
    return exp_mod(msg ,ca, p);
}

qint64 shamir_decoding(qint64 msg_code,qint64 cb, qint64 da, qint64 db, qint64 p)
{
    qDebug() << "X1 = " << msg_code;
    msg_code = exp_mod(msg_code, cb, p);
    qDebug() << "X2 = " << msg_code;
    msg_code = exp_mod(msg_code, da, p);
    qDebug() << "X3 = " << msg_code;
    return exp_mod(msg_code, db, p);
}
void gen_CxDx(QVector<qint64> &cxbx, qint64 p){
    qint64 gcd_mass[3];
    do{
        cxbx[0] = QRandomGenerator::global()->bounded(1, p);
    }while(GCD_two(cxbx[0], p-1) != 1);
    gcd(p-1,cxbx[0],gcd_mass);
    cxbx[1] = gcd_mass[2];

}
