#include <QCoreApplication>
#include "krypto.h"
#include <QRandomGenerator>
#include <iostream>
#include <QFile>
#include <fstream>
#include <string>
#include <typeinfo>
#include <QCryptographicHash>

QVector<qint64> rsa(QVector<qint64> message){
    qint64 pb, qb, nb, fi;
    QVector<qint64> cbdb(2,0);

    pb = gen_prime_num(1000, 10000);
    qb = gen_prime_num(1000, 10000);
    nb = pb * qb;
    qDebug() << pb << " " << qb;

    fi = (pb - 1) * (qb - 1);

    gen_CxDx(cbdb, fi+1);
    qDebug() << fi;
    qDebug() << cbdb;
    qint64 test;
    for(int i = 0; i < message.size(); i++){
        test = message[i];
        message[i] = exp_mod(message[i], cbdb[0],nb);
        qDebug() << "message = " << message[i];
        message[i] = exp_mod(message[i], cbdb[1],nb);
        //qDebug() << test << " " << message[i];
        if(message[i] != test){
            qDebug() << test << " " << message[i];
            exit(0);
        }
    }
    return message;
}
QVector<qint64> eg(QVector<qint64> message){
    qint64 i = QRandomGenerator::global()->bounded(1000000, 100000000);
    qint64 p = 0, q = 0, g = 0, ca = 0, da = 0, cb = 0, db = 0;
    for(; i > 100; i-- )
        if(is_prime_number(i)){
            if(is_prime_number((i*2)+1)){
                q = i;
                p = (q * 2)+1;
                break;
            }
        }
    do{
        g = QRandomGenerator::global()->bounded(2, p-2);
    }while(exp_mod(g,q,p)==1);
    ca = QRandomGenerator::global()->bounded(1, p-2);
    da = exp_mod(g, ca, p);
    cb = QRandomGenerator::global()->bounded(2, p-2);
    db = exp_mod(g, cb, p);
    for(int i = 0; i < message.size(); i++){
        message[i] = (message[i]%p * (exp_mod(db, ca, p)))%p;
        message[i] = (message[i]%p * (exp_mod(da, p-1-cb,p)))%p;
    }
    return message;
}
QVector<qint64> gost(QVector<qint64> message){
    qint32 q = 0, p = 0, g = 0, a = 0;

    qint32 low = qPow(2, 15), high = qPow(2,16);
    qint32 i = QRandomGenerator::global()->bounded(low, high);
    for(; i > 100; i-- ){
        if(is_prime_number(i)){
            if(is_prime_number((i*qPow(2,15))+1)){
                q = i;
                p = (q * qPow(2,15))+1;
                break;
            }
        }
    }

    do{
        g = QRandomGenerator::global()->bounded((quint32)1, (quint32)p);
        a = exp_mod(g, qPow(2,15), p);
    }while(a < 2 || exp_mod(a, q, p) != 1);

    qDebug()<< "Q = " << i << "P = q*2+1 = " << p << " A = " << a << " = = " << exp_mod(a, q, p);

    //gen key
    qint32 x,y; //x =sectr
    x = QRandomGenerator::global()->bounded((quint32)0, (quint32)q);
    y = exp_mod(a, x, p); // public key

    qint32 r = 0, k, s = 0, u1, u2;
    for(int i = 0; i < message.size(); i++){
        //code
        do{
            k = QRandomGenerator::global()->bounded((quint32)0, (quint32)q);
            r = (exp_mod(a, k, p)) % q;
            s = (k * message[i] + x * r) % q;
        }while(r == 0 || s == 0);
        qDebug() << " R = "<< r << " S = " <<s;
        //decode
        if(r <= 0 && s >= q) exit(1);
        qint32 inv;
        qint64 inv_ev[3];
        gcd(q, message[i], inv_ev);
        inv = inv_ev[2];
        if(inv < 0) inv += q;
        qDebug() << "inv = "<< inv << " message = "<< message[i] << " mod "<< q;
        u1 = (s * inv)%q;
        qDebug() <<" U1" <<u1;
        u2 = q + (-r * inv);
        while(u2 < 0){
            u2 += q;
        }
            qDebug() << "U2" << u2;
        if(r != ((exp_mod(a,u1,p) * exp_mod(y, u2, p))%p)%q){
            qDebug() << "hyu sosi + = " << ((exp_mod(a,u1,p) * exp_mod(y, u2, p))%p)%q;
        }
    }


    return message;
}
int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    QByteArray buf, hf_byte_arr;
    QVector<qint64> hf_byte_arr_toint;
    QFile in;

    std::string path_to_file = "/home/sigorut/1111";
    while(1){
        //std::cin >> path_to_file;
        in.setFileName(path_to_file.c_str());
        if(in.open(QIODevice::ReadOnly)){
            break;
        }
        qDebug() << "Такого файла не существует!";
    }
    QString out_file_name;
    out_file_name = path_to_file.c_str();
    buf = in.readAll();
    in.close();
    //qDebug() <<  buf;
    //считали бинарник
    hf_byte_arr = QCryptographicHash::hash(buf, QCryptographicHash::Md5); //вычислили хеш функцию
    qDebug() << "\nhf_byte_arr " << hf_byte_arr;
    hf_byte_arr = hf_byte_arr.toBase64();
    qDebug() << "\nhf_byte_arr_tobase() " << hf_byte_arr;
    for(int i = 0; i < hf_byte_arr.size(); i++){
        hf_byte_arr_toint << hf_byte_arr[i];
    }
    //RSA
    QVector<qint64> rsa_arr = rsa(hf_byte_arr_toint), eg_arr = eg(hf_byte_arr_toint), gost_arr = gost(hf_byte_arr_toint);
    for(int i = 0; i < hf_byte_arr_toint.size(); i++){
        if(hf_byte_arr_toint[i] != rsa_arr[i]){
            qDebug() << "not Good food RSA";
        }
        //EG
        if(hf_byte_arr_toint[i] != eg_arr[i]){
            qDebug() << "not Good food EG";
        }
        //GOST
        if(hf_byte_arr_toint[i] != gost_arr[i]){
            qDebug() << "not Good food GOST";
        }
    }
    qDebug() << hf_byte_arr_toint<< "\n" << rsa_arr << "\n" << eg_arr << "\n" << gost_arr;

    return a.exec();
}
