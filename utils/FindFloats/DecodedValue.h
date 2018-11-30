#ifndef DECODEDVALUE_H
#define DECODEDVALUE_H

#include <QString>
#include <QByteArray>
#include <QStringList>

class DecodedValue
{
public:
   DecodedValue(double base10Val, int offset, QByteArray bytes, QString dataType);

   double getBase10Value() { return theBase10Value; }

   int getOffset() { return theOffset; }

   int getNumberOfBytes() { return theBytes.length(); }

   QString getBytesHex() { return theBytes.toHex(' '); }

   QString getType() { return theType; }

   QStringList getTableData();

   bool operator==(DecodedValue const & rhs) const;
   bool operator!=(DecodedValue const & rhs) const;

   bool operator<(DecodedValue const & rhs) const;
   bool operator>(DecodedValue const & rhs) const;

   bool operator<=(DecodedValue const & rhs) const;
   bool operator>=(DecodedValue const & rhs) const;

protected:

   double theBase10Value;

   int theOffset;

   QByteArray theBytes;

   QString theType;
};





#endif // DECODEDVALUE_H
