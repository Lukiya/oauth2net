namespace OAuth2Net
{
    public class MessageResult<T>
    {
        public string Message { get; set; } = OAuth2Consts.Msg_Success;
        public T Result { get; set; }

        public bool IsSuccess => Message == OAuth2Consts.Msg_Success;
    }
}