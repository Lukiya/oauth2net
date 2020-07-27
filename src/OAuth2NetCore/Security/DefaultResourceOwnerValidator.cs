﻿using System.Threading.Tasks;

namespace OAuth2NetCore.Security
{
    /// <summary>
    /// DO NOT USE THIS
    /// </summary>
    public class DefaultResourceOwnerValidator : IResourceOwnerValidator
    {
        public Task<bool> VertifyAsync(string username, string password)
        {
            return Task.FromResult(false);
        }
    }
}
