using System.Threading.Tasks;

namespace OAuth2Net.Security
{
    public class NotSupportResourceOwnerValidator : IResourceOwnerValidator
    {
        private static MessageResult<bool> _r = new MessageResult<bool> { MsgCode = OAuth2Consts.Err_unsupported_response_type, Result = false };
        public Task<MessageResult<bool>> VertifyAsync(string username, string password)
        {
            return Task.FromResult(_r);
        }
    }
}
