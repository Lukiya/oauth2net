namespace System
{
    public static class Extensions
    {
        public static bool IsSuccess(this string msg)
        {
            return msg == OAuth2Net.Consts.Msg_Success;
        }
    }
}