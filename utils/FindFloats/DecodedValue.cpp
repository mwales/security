#include "DecodedValue.h"
#include <math.h>

DecodedValue::DecodedValue(double base10Val, int offset, QByteArray bytes, QString dataType):
   theBase10Value(base10Val),
   theOffset(offset),
   theBytes(bytes),
   theType(dataType)
{
   // Nothing
}

bool DecodedValue::operator==(DecodedValue const & rhs) const
{
   // This is really a terrible idea to compare doubles, but just something stupid here for
   // simple numbers
   return ( fabs(theBase10Value - rhs.theBase10Value) < 0.000001 );
}

bool DecodedValue::operator!=(DecodedValue const & rhs) const
{
   return ! (*this == rhs);
}

bool DecodedValue::operator<(DecodedValue const & rhs) const
{
   return theBase10Value < rhs.theBase10Value;
}

bool DecodedValue::operator>(DecodedValue const & rhs) const
{
   return theBase10Value > rhs.theBase10Value;
}

bool DecodedValue::operator<=(DecodedValue const & rhs) const
{
   return theBase10Value <= rhs.theBase10Value;
}

bool DecodedValue::operator>=(DecodedValue const & rhs) const
{
   return theBase10Value >= rhs.theBase10Value;
}

QStringList DecodedValue::getTableData()
{
   QStringList retVal;

   retVal << QString::number(theBase10Value);
   retVal << theType;
   retVal << getBytesHex();
   retVal << QString::number(theOffset);

   return retVal;
}
